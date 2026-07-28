# Mobile Traffic Inspector

Mobile Traffic Inspector là bảng điều hành tự lưu trữ, một quản trị viên, dùng để kiểm tra lưu lượng từ thiết bị iOS và Android **đã được cho phép**. Thiết bị đi vào một đường hầm WireGuard riêng; mitmproxy kết thúc đường hầm và truyền siêu dữ liệu/chunk nội dung đã mã hóa đến FastAPI + PostgreSQL. Bảng React hiển thị dữ liệu trực tiếp theo dạng danh sách/chi tiết và chỉ xóa bản ghi thô khi quản trị viên xác nhận.

Dự án dành cho chủ ứng dụng, đội QA và người kiểm thử bảo mật. Không được thu thập lưu lượng của thiết bị, tài khoản hoặc con người khi chưa có sự đồng ý. Nội dung bắt được có thể chứa mật khẩu, token và dữ liệu cá nhân.

## Phạm vi thu thập

Mọi flow đi qua WireGuard đều nằm trong phạm vi; không có allowlist theo tên miền. Addon ghi HTTP/1.1, HTTP/2, HTTP/3 khi mitmproxy hỗ trợ, tin nhắn WebSocket và siêu dữ liệu của kết nối TCP/UDP chưa hỗ trợ. Header request/response giữ nguyên thứ tự và bản sao. Nội dung được mã hóa theo chunk rồi ghi vào shared volume trong khi lưu lượng vẫn tiếp diễn, nhờ đó API ngừng hoạt động hoặc upload nhiều GB không tạo bộ đệm RAM vô hạn. Hàng đợi ingest có giới hạn sẽ spool siêu dữ liệu xuống đĩa khi API không sẵn sàng.

Nội dung HTTPS chỉ hiển thị khi ứng dụng tin CA thử nghiệm. Certificate pinning, mã hóa ở tầng ứng dụng, giao thức chưa hỗ trợ hoặc lưu lượng không đi qua tunnel sẽ được ghi là metadata/lỗi; hệ thống không tìm cách vượt qua chúng.

## Yêu cầu trước khi cài

- VPS Linux có Docker Engine và Docker Compose v2, ổ đĩa được mã hóa và quota phù hợp với lưu lượng cần giữ.
- DNS A/AAAA cho hostname trỏ về aaPanel/Nginx, cổng TCP/443 mở cho aaPanel và UDP/51820 mở cho WireGuard.
- aaPanel/Nginx đã bật SSL cho hostname và reverse proxy về cổng HTTP nội bộ của stack.
- `openssl`, `wg` và `curl` trên máy dùng để thiết lập.

## Khởi động nhanh trên VPS

```sh
git clone https://github.com/duogxaolin/mobile-traffic-inspector.git
cd mobile-traffic-inspector
cp .env.example .env
# Sửa SITE_ADDRESS và PANEL_HTTP_PORT nếu cần; chỉ đổi các giá trị khác khi hiểu rõ tác động.
./scripts/generate-secrets.sh
chmod 600 .env
chmod 644 secrets/*.txt
docker compose config -q
docker compose up -d --build
docker compose ps
```

Stack mặc định chỉ bind panel vào localhost, ví dụ `127.0.0.1:28080`, để không tranh cổng `443` với aaPanel và cũng dễ nhận ra port nội bộ. Trong aaPanel, tạo website/domain có SSL rồi reverse proxy toàn bộ domain về:

```text
http://127.0.0.1:28080
```

Bật hỗ trợ WebSocket nếu aaPanel có tùy chọn này. Nếu cần cấu hình Nginx thủ công, phần proxy tối thiểu là:

```sh
location / {
    proxy_pass http://127.0.0.1:28080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600;
}
```

Sau đó mở `https://$SITE_ADDRESS/` và đăng nhập `admin` bằng mật khẩu bootstrap do `generate-secrets.sh` in ra. Bảng điều khiển là HTTP API client duy nhất; PostgreSQL và ingest API không có host port. Không public trực tiếp `PANEL_HTTP_PORT`; port này nên chỉ nghe `127.0.0.1`.

### Cấu hình aaPanel/Nginx

Nếu bạn dùng aaPanel, chỉ cần tạo một site SSL cho `SITE_ADDRESS` rồi thêm reverse proxy tới:

```text
http://127.0.0.1:${PANEL_HTTP_PORT:-28080}
```

WebSocket phải được bật trong proxy. Nếu cấu hình bằng Nginx tay, giữ nguyên các header `X-Forwarded-*`, `Upgrade` và `Connection` như ví dụ ở trên. Không public `PANEL_HTTP_PORT` ra Internet.

### aaPanel 1 phút

1. Clone repo trên VPS và tạo `.env` từ `.env.example`.
2. Giữ `SITE_ADDRESS=domain-cua-ban` và `PANEL_HTTP_PORT=28080`.
3. Chạy:

```sh
./scripts/generate-secrets.sh
docker compose up -d --build
```

4. Trong aaPanel, bật SSL cho domain và reverse proxy về `http://127.0.0.1:28080`.
5. Mở `https://domain-cua-ban` để dùng panel.

Nếu repo đã tồn tại rồi, đừng `git clone` lại vào cùng thư mục. Chỉ cần:

```sh
cd /www/wwwroot/proxy/mobile-traffic-inspector
git pull --ff-only origin main
docker compose up -d --build
```

Nếu `./scripts/generate-secrets.sh` báo `Refusing to overwrite secrets/...`, đó là bình thường: secrets đã được tạo rồi. Chỉ chạy script này một lần khi cài mới, trừ khi bạn cố tình muốn xoay secret.

### Deploy lại / cập nhật trên VPS

Khi có commit mới trên `main`, đăng nhập VPS rồi chạy:

```sh
cd /srv/mobile-traffic-inspector
git pull --ff-only origin main
docker compose up -d --build
docker compose ps
docker compose logs api --tail 50
```

Sau đó mở lại `https://$SITE_ADDRESS/healthz` qua aaPanel/Nginx. Nếu đổi port nội bộ, sửa `PANEL_HTTP_PORT` trong `.env` và cập nhật target reverse proxy tương ứng.

Mặc định không tự xóa theo retention và không có quota body ở tầng ứng dụng. `RETENTION_DAYS` khác 0 xóa session quá hạn; `STORAGE_QUOTA_BYTES` khác 0 sẽ dọn các session cũ nhất sau khi flow hoàn tất (session đang hoạt động có thể tạm thời vượt giới hạn). `PREVIEW_BYTES` chỉ giới hạn phần bảng tải để xem trước, không cắt ngắn body đã mã hóa trên đĩa.

## Đăng ký thiết bị WireGuard và tin CA

Cách đơn giản nhất là làm ngay trong admin panel:

1. Mở **Devices / Setup**.
2. Nhập tên thiết bị, bấm **Generate profile**.
3. Quét QR bằng app WireGuard hoặc bấm **Download .conf** để tải profile.
4. Import profile vào WireGuard trên điện thoại được ủy quyền và bật tunnel.

Profile chứa private key, nên chỉ mở/tải trên máy admin tin cậy. Nút **Generate profile** cũng tự đăng ký hoặc kích hoạt lại peer tương ứng trong danh sách thiết bị. Nếu cần fallback bằng SSH, vẫn có thể chạy:

```sh
./scripts/extract-wireguard.sh ./device.conf
```

Profile hiện tại là profile client do mitmproxy tạo trong capture container, giống file mà script SSH copy ra. Hãy revoke bản ghi trước khi bỏ hoặc thay thiết bị.

Chỉ tải public proxy CA từ bảng điều khiển hoặc:

```sh
curl --fail --proto '=https' --tlsv1.2 -o mitmproxy-ca-cert.pem \
  "https://$SITE_ADDRESS/setup/mitmproxy-ca-cert.pem"
sha256sum mitmproxy-ca-cert.pem
```

Fingerprint do `./scripts/verify-ca.sh` hiển thị phải khớp giá trị trao đổi ngoài kênh với người kiểm thử. Không sao chép `mitmproxy-ca.pem` (CA private key) ra khỏi VPS. Trên Android, chỉ cài CA vào thiết bị test và dùng Network Security Configuration bản debug tin user certificate; ứng dụng release thường bỏ qua user CA. Trên iOS, cài profile rồi bật tin cậy tại **Settings → General → About → Certificate Trust Settings**. Lưu lượng ứng dụng vẫn phải đi qua device tunnel; app pin chứng chỉ máy chủ sẽ thất bại hoặc hiện `not-captured`, không bị bypass.

### WireGuard cần cài gì?

- Trên điện thoại: app WireGuard.
- Trên VPS: không cần cài tay nếu dùng repo này; `docker compose` đã dựng sẵn capture.
- Để đọc được HTTPS: cài thêm CA public của hệ thống vào điện thoại test và tin cậy nó.
- Để xem request: mở panel web, vào **Live Capture**, rồi bấm vào từng flow.

### Cách dùng tối giản

1. Cài app WireGuard trên điện thoại.
2. Trong admin panel vào **Devices / Setup**, bấm **Generate profile**.
3. Quét QR hoặc tải/import file `.conf`.
4. Bật tunnel.
5. Cài CA public của hệ thống.
6. Mở panel và kiểm tra request/response trong **Live Capture**.

Nếu app dùng certificate pinning hoặc tự đi đường riêng, bạn vẫn có thể thấy metadata và flow lỗi, nhưng không ép đọc nội dung HTTPS được.

## Luồng sử dụng bảng điều khiển

- **Live Capture** liệt kê flow của thiết bị đã đăng ký, lọc theo method/host/status/content type, dừng/tiếp tục ghi (network forwarding vẫn tiếp tục) và nhận stream WebSocket thời gian thực.
- Màn chi tiết có tab Request, Response, Timing và WebSocket. Header nhạy cảm, query value và giá trị JSON/form/text đã parse bị che mặc định. Xác thực lại mật khẩu admin cấp reveal token 60 giây; mọi reveal/export raw đều ghi audit trail. Export đã che là mặc định.
- **Sessions** liệt kê capture được giữ lại và yêu cầu API xác nhận trước khi xóa. **System / Audit** hiển thị body volume, dung lượng đĩa trống, ingest event đã spool/bị bỏ và thao tác nhạy cảm.

## Vận hành và bảo mật

Addon capture resolve lại từng đích ở thời điểm kết nối và chặn loopback, RFC1918/RFC4193/link-local, multicast, shared, cloud metadata và mọi địa chỉ không global khác. Điều này ngăn VPS trở thành open proxy hoặc đường SSRF. `SAFE_DESTINATION_OVERRIDES` là lối thoát tường minh của quản trị viên và nên để trống. Cookie bảng điều khiển là Secure, HttpOnly/SameSite và có CSRF protection; mật khẩu admin dùng Argon2id. Container bỏ capability khi tương thích, không dùng Docker socket, chỉ mở TCP/443 ở aaPanel/Nginx, TCP localhost cho panel nội bộ và UDP/51820 cho WireGuard.

Revoke thiết bị đã đăng ký sẽ chặn tunnel IP khỏi capture forwarding mới trong chu kỳ poll control của capture (thường ba giây); peer chưa đăng ký vẫn đủ điều kiện capture-all. Revoke không xóa được về mặt mật mã WireGuard profile đã cấp: để thu hồi key cứng, hãy xoay/tạo lại capture state và phân phối profile mới. Sao lưu PostgreSQL và encrypted body volume cùng application key. Mất application key khiến body đã mã hóa không thể khôi phục. Hãy coi backup là dữ liệu thô nhạy cảm. Xoay/revoke tài khoản admin và WireGuard peer khi mất máy trạm.

Khi gỡ bỏ, tắt device tunnel, revoke/xóa device record, gỡ CA profile khỏi mọi thiết bị test, chạy `docker compose down`, rồi giữ hoặc xóa named volume theo chính sách backup. Xem [docs/operations.md](docs/operations.md) để khôi phục, xác minh và xử lý sự cố.

## CI/CD qua GitHub Actions

Repository có hai workflow:

- **CI** chạy khi có pull request và khi push vào `main`: backend pytest, capture pytest, `npm ci`/test/build/audit cho `web`, kiểm tra Compose, shell syntax, YAML workflow, secret scan và Docker build.
- **Deploy VPS** chỉ chạy thủ công (`workflow_dispatch`) tại revision của `main`. Workflow dùng environment `production`, chạy preflight tương tự CI, SSH với host key đã khóa, rồi gọi `scripts/deploy-vps.sh` trên VPS bằng đúng `GITHUB_SHA`.

Các action được pin theo commit SHA và workflow chỉ có `contents: read`. Dependabot cập nhật GitHub Actions, npm và hai dependency pip theo lịch hàng tuần. `CODEOWNERS` yêu cầu `@duogxaolin` review các workflow và script deploy.

### Chuẩn bị VPS cho deploy

Vì repository là private, VPS cần một **GitHub deploy key đọc repository riêng** trước khi clone. Tạo key Ed25519 trên VPS cho mục đích này, thêm public key vào **Repository settings → Deploy keys** với quyền read-only, và xác minh GitHub SSH host key theo fingerprint công bố chính thức/trong kênh độc lập trước khi thêm vào `~/.ssh/known_hosts` của user deploy. Key này chỉ để VPS `git fetch` mã nguồn; nó không phải `VPS_SSH_PRIVATE_KEY` mà GitHub Actions dùng để đăng nhập vào VPS.

Sau đó clone SSH vào một thư mục riêng của user deploy (ví dụ `/srv/mobile-traffic-inspector` hoặc `/www/wwwroot/proxy/mobile-traffic-inspector` nếu bạn đi cùng aaPanel), tạo `.env` và `secrets/` bằng quy trình khởi động nhanh ở trên, rồi xác minh thủ công `docker compose up -d --build` hoạt động:

```sh
git clone git@github.com:duogxaolin/mobile-traffic-inspector.git /srv/mobile-traffic-inspector
```

User SSH phải chỉ có quyền cần thiết để chạy Docker Compose tại thư mục đó. Không chạy workflow bằng root.

Script deploy từ chối worktree có thay đổi cục bộ, lấy `origin/main`, chỉ chấp nhận SHA đúng bằng revision hiện tại của `origin/main`, dùng `flock` để chống deploy chồng nhau, và chạy `docker compose up -d --build --remove-orphans --wait`. Nó kiểm tra API/Caddy nội bộ lẫn `https://…/healthz` công khai. Khi lỗi sau lúc chuyển revision, script checkout lại revision trước và thử khởi động lại stack trước đó; không chạy `git reset --hard`, không xóa volume, `.env` hay secret.

Nếu bạn dùng aaPanel và đặt repo dưới `/www/wwwroot/...`, cứ dùng đúng đường dẫn đó xuyên suốt cho `git pull`, `docker compose ...` và `VPS_APP_DIR`. Điều quan trọng là một đường dẫn tuyệt đối duy nhất; không trộn `/srv/mobile-traffic-inspector` với `/www/wwwroot/proxy/mobile-traffic-inspector`.

Ứng dụng hiện không có migration orchestrator tự động. Vì vậy chỉ triển khai thay đổi schema tương thích ngược; với migration phá vỡ hoặc dữ liệu quan trọng, hãy backup PostgreSQL và encrypted body volume trước, thực hiện migration có kiểm soát, và chuẩn bị rollback dữ liệu riêng. Rollback container không thể tự đảo ngược migration dữ liệu.

### Cấu hình environment `production`

Trong GitHub, tạo environment tên `production` và bật required reviewers/protection rule phù hợp trước khi dùng deploy. Thêm các **Variables** sau:

| Variable | Ví dụ | Ý nghĩa |
| --- | --- | --- |
| `VPS_HOST` | `203.0.113.10` | IP/hostname VPS đã được kiểm soát |
| `VPS_USER` | `deploy` | User SSH không phải root |
| `VPS_PORT` | `22` | Cổng SSH |
| `VPS_APP_DIR` | `/srv/mobile-traffic-inspector` hoặc `/www/wwwroot/proxy/mobile-traffic-inspector` | Thư mục clone chuyên dụng trên VPS |
| `APP_URL` | `https://inspect.example.com` | URL HTTPS công khai qua aaPanel/Nginx, không có slash cuối |

Thêm hai **Secrets** sau:

| Secret | Nội dung |
| --- | --- |
| `VPS_SSH_PRIVATE_KEY` | Private key Ed25519 chỉ dùng cho deploy |
| `VPS_SSH_KNOWN_HOSTS` | Dòng known_hosts đúng cho `VPS_HOST:VPS_PORT`, đã xác minh fingerprint ngoài kênh |

Không dùng `ssh-keyscan` trong workflow: một host key mới không tự nhiên là host đáng tin. Lấy fingerprint từ console/provider hoặc kênh độc lập của quản trị viên VPS, so sánh với server bằng `ssh-keygen -lf`, sau đó lưu chính xác dòng known_hosts đã xác minh vào secret. Thay host key cần xác minh lại và cập nhật secret có chủ đích.

Ví dụ CLI (chạy trên máy quản trị; không commit file key/known_hosts):

```sh
gh variable set --env production VPS_HOST --body '203.0.113.10'
gh variable set --env production VPS_USER --body 'deploy'
gh variable set --env production VPS_PORT --body '22'
gh variable set --env production VPS_APP_DIR --body '/srv/mobile-traffic-inspector'
gh variable set --env production APP_URL --body 'https://inspect.example.com'
gh secret set --env production VPS_SSH_PRIVATE_KEY < ./deploy_ed25519
gh secret set --env production VPS_SSH_KNOWN_HOSTS < ./known_hosts.verified
```

Với repository private, hãy xác nhận gói GitHub/organization cho phép Actions, environment protection và reviewer bạn cần; chính sách/quyền phê duyệt có thể khác theo gói và organization. DNS thật, TCP/443, SSL ở aaPanel/Nginx và reverse proxy về `127.0.0.1:${PANEL_HTTP_PORT:-28080}` vẫn là điều kiện để panel public hoạt động. Workflow không biến hostname mẫu thành hệ thống public an toàn.

Sau khi CI của commit trên `main` xanh và environment được phê duyệt, chạy deploy có kiểm soát bằng:

```sh
gh workflow run deploy-vps.yml --ref main -f reason='Triển khai bản đã được phê duyệt'
```

Theo dõi log workflow, sau đó kiểm tra `https://…/healthz`, đăng nhập bảng điều khiển và kiểm tra `docker compose ps` trên VPS. Nếu deployment không qua health check, script đã thử rollback revision/container trước đó; hãy đọc log và trạng thái dữ liệu trước khi chạy lại.
