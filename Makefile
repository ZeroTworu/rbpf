.PHONY: elk

elk:
	docker-compose -f contrib/docker/docker-compose.infra.yaml up --remove-orphans
