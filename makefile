all:
	docker compose build
	docker compose up

delete:
	skopeo delete   --creds alice:secretpassword   --tls-verify=false   docker://skod.net/team1/registry:2

