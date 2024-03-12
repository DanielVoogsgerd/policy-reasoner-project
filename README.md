# policy-reasoner
Implements the famous policy reasoner, known as `checker` in Brane terminology. Builds on top of reasoners like [eFLINT](https://gitlab.com/eflint) and meant to be queried by [Brane](https://github.com/epi-project/brane).


# Setup for sqlite3 impl

Install diesel CLI
- `cargo install diesel_cli --no-default-features --feature sqlite`

Run diesel migration
- `cd lib/policy`
- `mkdir data`
- `diesel migration run --database-url data/policy.db`

Add active policy (requires `sqlite3` client)
- `sqlite3 ./data/policy.db`
- \[OLD DONT USE ANYMORE\] `INSERT INTO policies VALUES(1,'Dit is een omschrijving','Dit is een versie omschrijving','Bas Kloosterman',1698255086939846,readfile('./lib/reasonerconn/examples/example-policy-content.json')); INSERT INTO active_version VALUES(1,'2023-10-31 20:14:39.669660','Bas Kloosterman');`
- ```
  INSERT INTO policies VALUES(1,'Dit is een omschrijving','Dit is een versie omschrijving','Bas Kloosterman',1698255086939846,'[{"reasoner":"eflint","reasoner_version":"0.1.0","content":[]}]');
  INSERT INTO active_version VALUES(1,'2023-10-31 20:14:39.669660','Bas Kloosterman');
  ```
- Ctrl+D

# Example policy api calls

`
$ curl -v -X GET -H "Content-Type: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkEifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNjk5MjM5MDIyLCJleHAiOjE3OTkyMzkwMjIsInVzZXJuYW1lIjoiQmFzIEtsb29zdGVybWFuIn0.uuJWvZtD3VYtLfrM9qRp2xg401DO4muHZGS9lCuG5Po" http://localhost:3030/v1/policies
`

# Needed FIXES

// TODO: Check if needed
go eFlint server
- struct.go:156 remove omitempty json tag // of niet require empty array
- naming:
    - +user(HospitalA). -> +user(Hospitala).
    - Exists task, dataset' : ... -> Exists task, dataset2 :
- projection:
    - recipient.user == user => (recipient.user) == user
- negation:
