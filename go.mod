module github.com/SaaelCompany/tlswitch

go 1.22

require (
	github.com/coder/websocket v1.8.13
	github.com/kardianos/service v1.2.2
	go.cypherpunks.ru/gogost/v5 v5.14.1
	golang.org/x/net v0.31.0
	golang.org/x/sys v0.27.0
	gopkg.in/yaml.v3 v3.0.1
)

replace go.cypherpunks.ru/gogost/v5 => ./third_party/gogost

require golang.org/x/text v0.20.0 // indirect
