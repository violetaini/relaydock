    # 自动生成,RelayDock WSS 入站 nginx 反代配置。多个 WSS 入站合并渲染。
    server {
        listen                     443 ssl http2;
        listen                     [::]:443 ssl http2;
        server_name                {{.Domain}};

        ssl_certificate            /usr/local/nginx/cert/{{.CertName}}.pem;
        ssl_certificate_key        /usr/local/nginx/cert/{{.CertName}}.key;

        ssl_protocols              TLSv1.2 TLSv1.3;
        ssl_ciphers                ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers  on;

        index index.html;
        root  /usr/local/nginx/html;
{{range .Inbounds}}
        location = {{.WSPath}} {
            if ($http_upgrade != "websocket") { return 404; }
            proxy_pass         http://127.0.0.1:{{.Port}};
            proxy_redirect     off;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade            $http_upgrade;
            proxy_set_header   Connection         "upgrade";
            proxy_set_header   Host               $host;
            proxy_set_header   X-Real-IP          $remote_addr;
            proxy_set_header   X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_read_timeout 5d;
        }
{{end}}

        # 兜底:精确 location 未命中(也包括 WSS 入站全删完时)按站点伪装配置处理,默认 404。
        # 精确匹配 `location = /ws/xxx` 优先级高于前缀 `/`,正常 WSS 流量不受影响。
{{- if eq .SiteType "proxy" }}
        location / {
            if ($host != "{{.Domain}}") { return 444; }
            if ($http_upgrade != "") { return 404; }
            proxy_pass              {{.ProxyPassServer}};
            proxy_redirect          off;
            proxy_http_version      1.1;
            proxy_ssl_server_name   on;
            proxy_ssl_name          $proxy_host;
            proxy_ssl_protocols     TLSv1.2 TLSv1.3;
            proxy_set_header Host               $proxy_host;
            proxy_set_header X-Real-IP          $remote_addr;
            proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto  $scheme;
            proxy_set_header Accept-Encoding    "";
        }
{{- else if .StaticRootPath }}
        location / {
            root   {{.StaticRootPath}};
            index  index.html index.htm;
        }
{{- else }}
        location / {
            return 404;
        }
{{- end }}
    }
