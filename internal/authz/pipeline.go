package authz

import "context"

// Pipeline is the production Authorizer: identity → reenroll-must-auth →
// inventory → challenge → authenticated? → role → constraints. Any gap denies.
type Pipeline struct {
	Inventory        Inventory          // nil ⇒ NoInventory (all devices permitted)
	Challenge        ChallengeValidator // nil ⇒ no validator (required challenges deny)
	Roles            RoleSelector       // required
	Constraints      ConstraintBuilder  // required
	RequireChallenge bool               // global: force challenge validation
	// AllowUnauthenticated permits enrollment proving nothing. Off by default;
	// see the authentication gate in Authorize for why the inventory is not proof.
	AllowUnauthenticated bool
}

// Authorize implements Authorizer.
func (p *Pipeline) Authorize(ctx context.Context, req Request) (Decision, error) {
	// (1) Identity: authenticated cert attributes vs what the CSR requests.
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

	// (4) Challenge. challengeValidated needs a NON-EMPTY secret: an empty one
	// proves nothing even where a permissive validator accepts it.
	challengeValidated := false
	challengeRequired := p.RequireChallenge || rec.RequireChallenge
	if challengeRequired {
		if p.Challenge == nil {
			return Deny("challenge required but no validator configured"), nil
		}
		if err := p.Challenge.Validate(ctx, id, req.ChallengePassword); err != nil {
			return Deny("challenge validation failed"), nil
		}
		challengeValidated = req.ChallengePassword != ""
	} else if req.ChallengePassword != "" && p.Challenge != nil {
		// A supplied-but-not-required challenge is still validated, so a wrong
		// secret is a hard failure rather than being silently ignored.
		if err := p.Challenge.Validate(ctx, id, req.ChallengePassword); err != nil {
			return Deny("challenge validation failed"), nil
		}
		challengeValidated = true
	}

	// (5) Authentication gate. The inventory matched a name the REQUESTER chose —
	// "is this name permitted?", never "are you that device?". See T14.
	if !id.Authenticated && !challengeValidated && !p.AllowUnauthenticated {
		return Deny("unauthenticated: no client certificate and no validated challenge"), nil
	}

	// (6) Role selection.
	role := rec.Role
	if role == "" && p.Roles != nil {
		role = p.Roles.Role(id)
	}
	if role == "" {
		return Deny("no OpenBao role for identity"), nil
	}

	// (7) Constraint policy.
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
