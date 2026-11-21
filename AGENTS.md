# AI agent guidance

Apply this guide to changes throughout the repository. It records the
maintainer's Go style preferences for implementation and review.

## Repository context

This project is a Linux DHCPv4 worker. Read the [development instructions](README.md#development-and-tests),
[technical specification](TechnicalSpecification.md) and
[threat model](ThreatModel.md) before changing behavior. Preserve their
protocol, persistence and security requirements when applying
the style defaults below.

Use the existing package responsibilities. General backend examples in this
guide do not require adding HTTP, database or service layers to the DHCP worker.
Apply the preferences to the code being changed; keep unrelated architectural
and style refactors out of the change.

## Naming and local readability

- Use `gofmt` for Go formatting.
- Mix conventional names such as `ctx`, `db` and `err` with descriptive domain
  names such as `userID` or `leaseDuration`.
- Let package and receiver context determine naming detail. Prefer explicit
  names in broad contexts and shorter names when the surrounding type already
  makes the subject clear.
- Keep small, single-use conditions inline. Extract helpers when meaningful
  reuse or the complexity of an operation justifies them.

## Packages and dependencies

- Prefer organization by technical responsibility, such as handlers, services
  and repositories, while preserving this repository's existing boundaries.
- Start with concrete dependencies. Introduce an interface for a demonstrated
  need, including isolated tests of business logic.
- Put small interfaces beside their consumers and include only the operations
  those consumers require. Use handwritten fakes for business-logic tests.
- Prefer standard-library HTTP routing and handlers when they meet the
  requirements. This preference is not a blanket ban on third-party packages.
- Choose database access tooling per project; there is no fixed preference
  among handwritten SQL, generated bindings and ORMs.

## Construction and configuration

- Keep service dependencies in private fields and expose explicit constructors.
- Pass dependencies as explicit arguments. Group operational settings in a
  configuration struct, separate from dependencies.
- Panic immediately when an internal constructor is called without a required
  dependency. This represents a programmer wiring error. Return errors for
  invalid external configuration, malformed input and runtime failures.

Illustrative constructor excerpt (imports and type declarations omitted):

```go
func NewUserService(
	store userStore,
	logger *slog.Logger,
	config ServiceConfig,
) *UserService {
	if store == nil {
		panic("services: user store is required")
	}
	if logger == nil {
		panic("services: logger is required")
	}
	return &UserService{
		store:  store,
		logger: logger,
		config: config,
	}
}
```

An interface dependency must also not contain a typed nil pointer; a simple
`store == nil` check only detects a nil interface.

## Domain values and transport inputs

- Put business validation that applies across entry points in domain
  constructors.
- Export ordinary data fields. Use private fields and validating methods when
  protecting continuing invariants justifies the extra methods.
- For HTTP services, decode directly into service input structs, with JSON tags
  on those structs. Shared transport/service inputs are the default.

Illustrative domain constructor:

```go
var ErrInvalidName = errors.New("invalid user name")

type User struct {
	Name string
}

func NewUser(name string) (User, error) {
	if strings.TrimSpace(name) == "" {
		return User{}, ErrInvalidName
	}
	return User{Name: name}, nil
}
```

## Errors and logging

- Use sentinel errors for expected failures. Callers distinguish them with
  `errors.Is`.
- Add operation context when propagating errors through each layer, preserving
  the underlying error with `%w`.
- Log unexpected failures where they originate. Higher layers wrap and handle
  the returned error without duplicating the log.
- Return expected outcomes, such as a missing record or business rejection,
  without logging them.
- Follow the repository's existing bounds and sanitization requirements for
  errors and logs.

```go
user, err := domain.NewUser(input.Name)
if err != nil {
	return domain.User{}, fmt.Errorf("create user: %w", err)
}

if err := s.store.CreateUser(ctx, user); err != nil {
	return domain.User{}, fmt.Errorf("create user: %w", err)
}
```

## Transactions and concurrency

- Start with an atomic repository operation owning its transaction. Introduce
  a service-composed transaction callback when multiple workflows need
  different combinations of writes.
- Prefer inline standard-library concurrency coordination. Keep goroutine
  ownership, cancellation, error collection and completion visible at the call
  site. Additional lines alone are not a reason to add `errgroup` or a shared
  concurrency helper.

## Tests and verification

- Prefer table-driven tests with standard-library checks such as `t.Fatal`,
  `t.Fatalf` and `errors.Is`.
- Use small handwritten fakes when interfaces are introduced for business-logic
  tests.
- Follow the [development instructions](README.md#development-and-tests) for behavior tests and verification:
  `python3 tests/release_gates.py`, `go test ./...` and
  `golangci-lint run ./...` using the documented version. CI supplies additional
  race, pure-Go, fuzz, security and isolated systemd checks.
- Describe the change and useful verification results in the PR. State any
  unavailable checks accurately.

## Choices that remain project-specific

The style profile does not prescribe database libraries, migration tooling or
integration-test infrastructure. Go versions, lint rules and dependencies for
this repository remain governed by its checked-in configuration and documents.
