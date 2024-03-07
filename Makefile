.PHONY: create-db
create-db:
	cd ./lib/policy
	rm -rf data || true
	mkdir data

.PHONY: migrate
migrate:
	diesel migration run --database-url data/policy.db

.PHONY: seed
seed:
	sqlite3 data/policy.db < ./seeds/2024-03-07-00:00:00-policies.sql
	sqlite3 data/policy.db < ./seeds/2024-03-07-00:00:01-active_version.sql
	
.PHONY: setup
setup: create-db migrate seed
