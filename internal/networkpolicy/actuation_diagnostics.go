package networkpolicy

// Only this package can construct these fixed, bounded diagnostic stages. An
// arbitrary OwnedRoute error must never be forwarded into workload evidence.
type actuationStage uint8

const (
	actuationCommandRefused actuationStage = iota + 1
	actuationCommandCancelled
	actuationReadbackInvalid
	actuationIdentityChanged
)

type actuationFailure struct{ stage actuationStage }

func (e *actuationFailure) Error() string {
	label := "unknown stage"
	if e != nil {
		switch e.stage {
		case actuationCommandRefused:
			label = "command refused"
		case actuationCommandCancelled:
			label = "command deadline or cancellation"
		case actuationReadbackInvalid:
			label = "kernel readback invalid"
		case actuationIdentityChanged:
			label = "kernel identity changed"
		}
	}
	return ErrActuation.Error() + ": " + label
}
func (*actuationFailure) Unwrap() error { return ErrActuation }
