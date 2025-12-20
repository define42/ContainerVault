all:
	docker compose build

test:
	docker compose down
	docker compose build
	docker compose up -d
	google-chrome --no-sandbox --ignore-certificate-errors --disable-application-cache   --disk-cache-size=1  --media-cache-size=1  --user-data-dir=/tmp/chrome-nocache --no-first-run --no-default-browser-check https://localhost

delete:
	skopeo delete   --creds alice:secretpassword   --tls-verify=false   docker://skod.net/team1/registry:2

