SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 0;

DELETE FROM inquiries;
DELETE FROM reviews;
DELETE FROM coupons;
DELETE FROM products;
DELETE FROM notices;
DELETE FROM users;

INSERT INTO users (id, username, password, display_name, email, role) VALUES
    (1, 'admin', 'training-admin-only', 'Lumi 관리자', 'admin@example.test', 'admin'),
    (2, 'analyst', 'training-analyst-only', '보안 분석가', 'analyst@example.test', 'analyst'),
    (3, 'guest', 'guest', '게스트 회원', 'guest@example.test', 'member');

INSERT INTO products
    (id, name, category, price, original_price, description, badge, rating, review_count, stock, accent)
VALUES
    (1, 'Nova 무선 헤드폰', '디지털', 129000, 159000, '공간 음향과 40시간 배터리를 갖춘 데일리 무선 헤드폰입니다.', 'BEST', 4.8, 284, 18, 'violet'),
    (2, 'Orbit 스마트 워치', '디지털', 189000, 229000, '운동과 수면을 기록하고 일상의 알림을 간편하게 확인합니다.', 'NEW', 4.7, 116, 12, 'blue'),
    (3, 'Cloud 미니 가습기', '리빙', 34900, 42000, '조용한 분사와 은은한 무드등을 제공하는 데스크용 가습기입니다.', 'SALE', 4.6, 92, 31, 'mint'),
    (4, 'Mellow 테이블 램프', '리빙', 58000, NULL, '세 단계 밝기와 따뜻한 색온도를 지원하는 무선 조명입니다.', NULL, 4.9, 77, 9, 'orange'),
    (5, 'Daypack 22L', '패션', 79000, 99000, '노트북 수납과 생활 방수를 지원하는 가벼운 데일리 백팩입니다.', 'BEST', 4.7, 205, 24, 'green'),
    (6, 'Sunday 코튼 셔츠', '패션', 49000, NULL, '계절에 관계없이 편안하게 입을 수 있는 여유로운 핏의 셔츠입니다.', NULL, 4.5, 63, 42, 'rose'),
    (7, 'Focus 데스크 매트', '문구', 27000, 32000, '부드러운 표면과 미끄럼 방지 바닥을 갖춘 와이드 데스크 매트입니다.', 'SALE', 4.8, 149, 37, 'navy'),
    (8, 'Write Better 노트', '문구', 12000, NULL, '아이디어를 구조화하기 좋은 도트 그리드 하드커버 노트입니다.', NULL, 4.6, 88, 55, 'yellow');

INSERT INTO reviews (id, author, title, content, rating) VALUES
    (1, '민지', '배송이 빠르고 포장이 꼼꼼해요', '주문 다음 날 도착했고 제품 상태도 좋았습니다.', 5),
    (2, '준호', '일상에서 자주 사용하고 있어요', '설명과 실제 제품이 같고 사용법도 간단합니다.', 4),
    (3, '서연', '선물용으로 만족합니다', '디자인이 깔끔해서 선물 받은 분도 좋아했어요.', 5);

INSERT INTO notices (id, title, content) VALUES
    (1, '배송 일정 안내', '평일 오후 2시 이전 결제 건은 당일 출고됩니다.'),
    (2, '교환 및 반품 정책', '상품 수령 후 7일 이내 고객센터로 접수해 주세요.'),
    (3, '신규 회원 혜택', '가입 즉시 사용할 수 있는 웰컴 쿠폰을 제공합니다.');

INSERT INTO coupons (id, code, discount_percent, active, expires_at) VALUES
    (1, 'WELCOME10', 10, 1, '2026-12-31'),
    (2, 'LUMI20', 20, 1, '2026-09-30'),
    (3, 'EXPIRED5', 5, 0, '2026-01-31');

SET FOREIGN_KEY_CHECKS = 1;
