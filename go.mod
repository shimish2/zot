module github.com/anuvu/zot

go 1.13

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000
	github.com/chartmuseum/auth v0.4.0
	github.com/getlantern/deepcopy v0.0.0-20160317154340-7f45deb8130a
	github.com/go-chi/chi v4.0.2+incompatible // indirect
	github.com/go-ldap/ldap/v3 v3.1.3
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/json-iterator/go v1.1.9
	github.com/mitchellh/mapstructure v1.1.2
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/nmcclain/ldap v0.0.0-20191021200707-3b3b69a7e9e3
	github.com/opencontainers/distribution-spec v1.0.0-rc0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/opencontainers/umoci v0.4.6
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rs/zerolog v1.17.2
	github.com/smartystreets/goconvey v1.6.4
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.6.1
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.3
	go.etcd.io/bbolt v1.3.4
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	gopkg.in/resty.v1 v1.12.0
)

replace github.com/aquasecurity/trivy => github.com/anuvu/trivy v0.9.2-0.20200624055514-7fa927d7ca1d

replace github.com/aquasecurity/fanal => github.com/anuvu/fanal v0.0.0-20200623180831-a648790ef38e

replace github.com/aquasecurity/trivy-db => github.com/anuvu/trivy-db v0.0.0-20200623200932-d185809a68f7
