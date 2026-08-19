package classify

// Version rises whenever a rule changes in a way that can change the class of
// a value. init writes it into the project state, and a later run compares it,
// so a project that was veiled by an older set of rules can be told to run
// init again.
//
// Raise it in the same commit as the rule change. TestVersionRisesWithTheRules
// fails when the golden decisions move and this number does not.
const Version = 3
