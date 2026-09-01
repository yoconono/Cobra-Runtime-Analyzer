# Convenience targets for a Cobra CVE server deployment.
STORE ?= mariadb
DSN   ?= $(CVE_DSN)
CONF  ?= /etc/cobrart/cobrart.conf

.PHONY: migrate refresh token install-config install-units
migrate:            ## create/upgrade the schema
	cobra migrate --store $(STORE) --dsn "$(DSN)"

refresh:            ## pull all feeds once (tracker + NVD/OSV + KEV + EPSS)
	cobra refresh --config $(CONF) --source both --nvd-api-key "$(NVD_API_KEY)"

token:              ## issue an enrollment token (DESC=, MAX=)
	cobra create-token --store $(STORE) --dsn "$(DSN)" --desc "$(DESC)" --max-uses $(MAX)

install-config:     ## install the config template (edit it before starting!)
	install -d -m0750 /etc/cobrart /etc/cobrart/tls
	test -f /etc/cobrart/cobrart.conf || install -m0640 cobrart.conf.example /etc/cobrart/cobrart.conf

install-units: install-config  ## install systemd service + refresh timer
	install -m0644 cobrart.service cobrart-refresh.service cobrart-refresh.timer /lib/systemd/system/
	systemctl daemon-reload
	systemctl enable --now cobrart.service cobrart-refresh.timer
