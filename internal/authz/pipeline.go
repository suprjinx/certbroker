package authz

import (
	"context"
	"log/slog"
)

// Pipeline is the production Authorizer. It runs a fixed sequence of stages,
// every one of which must pass, and fails closed: any missing component,
// uncertain result, or error denies issuance.
//
// Stages, in order:
//  1. Identity resolution (mTLS cert + CSR).
//  2. Re-enrollment must be authenticated by a client certificate.
//  3. Inventory: the device must be permitted (unless NoInventory).
//  4. Challenge: validate the challengePassword when required (globally, or by
//     the inventory record, or whenever one is supplied).
//  5. Role selection: identity → OpenBao role (record override wins).
//  6. Constraint policy: derive the bounded CN/SANs/TTL actually requested.
type Pipeline struct {
	Inventory        Inventory          // nil ⇒ NoInventory (all devices permitted)
	Challenge        ChallengeValidator // nil ⇒ no validator (required challenges deny)
	Roles            RoleSelector       // required
	Constraints      ConstraintBuilder  // required
	RequireChallenge bool               // global: force challenge validation
	Logger           *slog.Logger
}

// Authorize implements Authorizer.
func (p *Pipeline) Authorize(ctx context.Context, req Request) (Decision, error) {
	id := resolveIdentity(req)

	// (2) Re-enrollment continuity requires an authenticated client cert.
	if req.Operation == OpSimpleReenroll && !id.Authenticated {
		return Deny("re-enrollment requires a client certificate"), nil
	}

	// (3) Inventory.
	inv := p.Inventory
	if inv == nil {
		inv = NoInventory{}
	}
	rec, err := inv.Lookup(ctx, id)
	if err != nil {
		return Decision{}, err // infrastructure error: surface, do not silently deny
	}
	if !rec.Found {
		return Deny("device not permitted by inventory"), nil
	}

	// (4) Challenge password.
	challengeRequired := p.RequireChallenge || rec.RequireChallenge
	if challengeRequired {
		if p.Challenge == nil {
			return Deny("challenge required but no validator configured"), nil
		}
		if err := p.Challenge.Validate(ctx, id, req.ChallengePassword); err != nil {
			return Deny("challenge validation failed"), nil
		}
	} else if req.ChallengePassword != "" && p.Challenge != nil {
		// A supplied-but-not-required challenge is still validated, so a wrong
		// secret is a hard failure rather than being silently ignored.
		if err := p.Challenge.Validate(ctx, id, req.ChallengePassword); err != nil {
			return Deny("challenge validation failed"), nil
		}
	}

	// (5) Role selection.
	role := rec.Role
	if role == "" && p.Roles != nil {
		role = p.Roles.Role(id)
	}
	if role == "" {
		return Deny("no OpenBao role for identity"), nil
	}

	// (6) Constraint policy.
	if p.Constraints == nil {
		return Deny("no constraint policy configured"), nil
	}
	cons, err := p.Constraints.Build(id, rec)
	if err != nil {
		return Deny(err.Error()), nil
	}

	return Decision{
		Allow:       true,
		Role:        role,
		Constraints: cons,
		Reason:      "authorized",
	}, nil
}
