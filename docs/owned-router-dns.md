# Owned router DNS sockets

The closed mapped router child creates exactly one UDP and one listening TCP
socket at `10.0.1.1:53` in its fresh private network namespace. It uses a fixed
`IP_FREEBIND` address before the private link is configured, not a wildcard or a
host listener. It transfers exactly two descriptors over a private inherited
Unix sequence-packet socket, closes its copies and the transfer channel, and
then drops all capabilities before reporting readiness. No worker-provided
command, path, endpoint or descriptor is accepted by this exchange.

The parent checks message/ancillary bounds, descriptor count, socket domain,
transport, listening state and exact bound address. It obtains each socket's
actual namespace with `SIOCGSKNS` and compares that kernel identity with the
retained router namespace. Linux performs this operation against the socket's
namespace and requires `CAP_NET_ADMIN` there. See the
[kernel socket ioctl implementation](https://github.com/torvalds/linux/blob/master/net/socket.c).
Labels and a matching IP are not namespace proof. Revalidation repeats these
checks and permanently refuses a failed owner; all refused descriptors close.

The measured session starts `AuthorityRoute.ServeDNS` only after installing the
native firewall. The server uses the existing bounded DNS parser, current
installed binding view, exact workload peer `10.0.1.2`, connection/query limits
and shared firewall accounting. UDP/TCP failure withdraws the route and stops
the workload. Session retirement waits for the DNS server and its accepted
connections to stop, in addition to process, firewall, link and bundle cleanup.
Router cleanup closes the transferred listeners even if no server was started.

Disposable Sentry sessions exercise A and AAAA answers over both UDP and TCP,
unlisted-name refusal, normal completion, router loss and deliberate UDP
listener failure during live workload traffic. Socket checks reject the host
namespace and the wrong transport while accepting the exact router socket;
every router thread must still have zero capabilities and no-new-privileges.
Cold controller recovery also includes the new namespace-holding descriptors.

This is not public DNS, an arbitrary recursive resolver, global capacity proof,
or production activation. Names come only from authenticated effective policy
bindings. Default resolver-file configuration is supplied by the
[protected measured bundle](measured-guest-resolver.md). Service admission,
global limits, Paper/secret/event integration and hosted acceptance remain open.
