package guestoutput

import "io"

// The measured helper emits this before reading bootstrap input. Its root owner
// consumes it (never relays it as guest output), observes the live kernel owners,
// and only then supplies configuration. It is a synchronization marker, not
// runtime evidence or permission; observation failure still withdraws the job.
const startupMarker = "PVREADY1"

func WriteStartup(writer io.Writer) error {
	if writer == nil {
		return ErrStream
	}
	n, err := io.WriteString(writer, startupMarker)
	if err != nil {
		return err
	}
	if n != len(startupMarker) {
		return io.ErrShortWrite
	}
	return nil
}

// The caller must bind cancellation/deadline to the owned pipe before reading.
func ReadStartup(reader io.Reader) error {
	if reader == nil {
		return ErrStream
	}
	var raw [len(startupMarker)]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return err
	}
	if string(raw[:]) != startupMarker {
		return ErrStream
	}
	return nil
}
