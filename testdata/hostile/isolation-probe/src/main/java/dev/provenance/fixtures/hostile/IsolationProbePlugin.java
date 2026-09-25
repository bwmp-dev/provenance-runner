package dev.provenance.fixtures.hostile;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.util.Map;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * WP-11C isolation probe fixture (hostile).
 *
 * <p>When enabled inside a sandboxed job this plugin actively attempts every
 * escape an untrusted plugin would try: reaching PostgreSQL (5432) and Temporal
 * (7233) on common private/management addresses, the Coolify management host,
 * the cloud instance metadata endpoint, the Docker/containerd control sockets,
 * host PID/network namespace escapes, reading sibling job directories, and
 * scraping the process environment for credentials. Each attempt prints one
 * structured line:
 *
 * <pre>PROBE &lt;name&gt; PASS      isolation held (the attempt was denied)
 * PROBE &lt;name&gt; REACHED   containment failure (the attempt succeeded)</pre>
 *
 * <p>The Plan 03 exit gate asserts every probe reports PASS. The fixture is
 * inert unless {@code -Dprovenance.fixture.hostile.enabled=true} is set, so the
 * default fixture build and unit suites never execute it. It must run only
 * inside a disposable, resource-limited gVisor job — never against production.
 * The plain-shell equivalent lives in
 * {@code internal/provider/gvisor/isolation_probe_linux_test.go}.
 */
public final class IsolationProbePlugin extends JavaPlugin {

  @Override
  public void onEnable() {
    requireOptIn();
    // Data-plane and management services on private/management addresses.
    tcp("postgres_private_a", "10.0.0.1", 5432);
    tcp("postgres_private_b", "172.17.0.1", 5432);
    tcp("postgres_loopback", "127.0.0.1", 5432);
    tcp("temporal_private_a", "10.0.0.1", 7233);
    tcp("temporal_private_b", "192.168.1.1", 7233);
    tcp("coolify_mgmt_http", "10.0.0.1", 8000);
    tcp("coolify_mgmt_https", "10.0.0.1", 443);
    // Cloud instance metadata.
    http("cloud_metadata", "http://169.254.169.254/latest/meta-data/");
    http("cloud_metadata_ecs", "http://169.254.170.2/v2/credentials");
    // Container control plane.
    absent("docker_socket", "/var/run/docker.sock");
    absent("docker_socket_run", "/run/docker.sock");
    absent("containerd_socket", "/run/containerd/containerd.sock");
    // Host PID / network namespace escapes.
    absent("host_init_ns", "/proc/1/ns/net");
    unreadable("host_init_root", "/proc/1/root/etc/shadow");
    unreadable("read_etc_shadow", "/etc/shadow");
    unreadable("read_host_home", "/root/.ssh/id_rsa");
    // Cross-job filesystem reads (sibling job directories under the inputs root).
    unreadable("read_other_job", "/inputs/../smoke-cancel/tenant-secret");
    // Environment credential scraping.
    envScrape();
    identity();
    System.out.println("PROBE_COMPLETE");
  }

  private static void tcp(String name, String host, int port) {
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress(host, port), 2_000);
      reached(name);
    } catch (IOException | RuntimeException denied) {
      pass(name);
    }
  }

  private static void http(String name, String url) {
    try {
      HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
      connection.setConnectTimeout(2_000);
      connection.setReadTimeout(2_000);
      connection.getResponseCode();
      reached(name);
    } catch (IOException | RuntimeException denied) {
      pass(name);
    }
  }

  private static void absent(String name, String path) {
    verdict(name, !new File(path).exists());
  }

  private static void unreadable(String name, String path) {
    verdict(name, !new File(path).canRead());
  }

  private static void envScrape() {
    for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
      if (entry.getKey().toUpperCase().matches(".*(PASSWORD|SECRET|TOKEN|CREDENTIAL|DATABASE_URL|AWS_|S3_|TEMPORAL).*")) {
        reached("env_scrape");
        return;
      }
    }
    pass("env_scrape");
  }

  private static void identity() {
    // A hosted job must run as the unprivileged container user, never root.
    verdict("identity_not_root", !"root".equals(System.getProperty("user.name")));
  }

  private static void verdict(String name, boolean isolated) {
    if (isolated) {
      pass(name);
    } else {
      reached(name);
    }
  }

  private static void pass(String name) {
    System.out.println("PROBE " + name + " PASS");
  }

  private static void reached(String name) {
    System.out.println("PROBE " + name + " REACHED");
  }

  private static void requireOptIn() {
    if (!Boolean.getBoolean("provenance.fixture.hostile.enabled")) {
      throw new IllegalStateException("hostile fixture execution requires explicit opt-in");
    }
  }
}
