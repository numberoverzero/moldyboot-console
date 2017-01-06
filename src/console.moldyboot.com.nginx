server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name console.moldyboot.com;

    access_log /var/log/nginx/console/access.log;
    error_log  /var/log/nginx/console/error.log;

    root /services/console/static;

    # =============
    #  Pretty Urls
    # =============

    # remove trailing "/"
    # -------------------
    rewrite ^/(.*)/$ /$1 permanent;

    # remove trailing ".html"
    # -----------------------
    rewrite ^/(.*)\.html$ /$1 permanent;


    # search rules
    # ------------
    # 0. name as given (css/normalize.min.css)
    # 1. append .html for single pages (/login -> /login.html)
    # 2. append /index.html for directories (/users -> /users/index.html)
    location / {
        try_files $uri $uri.html $uri/index.html =404;
    }
}
