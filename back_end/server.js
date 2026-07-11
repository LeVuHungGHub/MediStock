const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
const path = require('path');
app.use(express.static(__dirname));
app.use(express.static('E:/web_Pharmar/font_end_managements'));
// Cấu hình kết nối MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '01012005',
    database: 'pharmakeep_db'
});

db.connect((err) => {
    if (err) {
        console.error('Lỗi kết nối MySQL:', err.message);
        return;
    }
    console.log('Đã kết nối thành công tới Database: pharmakeep_db');

    // TRÁNH LỖI COPY TAY: TỰ ĐỘNG ĐỒNG BỘ LẠI TÀI KHOẢN CHUẨN 100% KHI CHẠY SERVER
    const plainPassword = '123456';
    const emailAdmin = 'nguyentuancuong01dng@gmail.com';

    bcrypt.hash(plainPassword, 10, (err, hash) => {
        if (err) return console.error('Lỗi tạo hash:', err);

        // Kiểm tra xem user này đã có chưa, nếu có rồi thì update lại hash chuẩn 60 ký tự
        const checkQuery = 'SELECT * FROM users WHERE email = ?';
        db.query(checkQuery, [emailAdmin], (checkErr, results) => {
            if (results && results.length > 0) {
                const updateQuery = 'UPDATE users SET password_hash = ? WHERE email = ?';
                db.query(updateQuery, [hash, emailAdmin], () => {
                    console.log('=== [HỆ THỐNG] ĐÃ ĐỒNG BỘ MẬT KHẨU 123456 CHUẨN (60 KÝ TỰ) VÀO DB! ===');
                });
            } else {
                const insertQuery = 'INSERT INTO users (email, password_hash) VALUES (?, ?)';
                db.query(insertQuery, [emailAdmin, hash], () => {
                    console.log('=== [HỆ THỐNG] ĐÃ TẠO MỚI TÀI KHOẢN ADMIN CHUẨN VÀO DB! ===');
                });
            }
        });
    });
});

// API Đăng nhập
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // THAY ĐỔI QUAN TRỌNG: Sửa chữ 'users' thành 'staff' ở câu lệnh SQL
        const query = 'SELECT * FROM staff WHERE email = ?';

        const [staffList] = await db.promise().query(query, [email]);

        // Kiểm tra xem email có tồn tại trong bảng staff không
        if (staffList.length === 0) {
            return res.status(401).json({ message: "Email không tồn tại trong hệ thống." });
        }

        const staffMember = staffList[0];

        // Kiểm tra tài khoản có bị khóa không
        if (staffMember.account_status !== 'active') {
            return res.status(403).json({ message: "Tài khoản của bạn đã bị vô hiệu hóa." });
        }

        // So sánh mật khẩu người dùng nhập với mật khẩu mã hóa trong database
        const isMatch = await bcrypt.compare(password, staffMember.password_hash);

        if (!isMatch) {
            return res.status(401).json({ message: "Sai mật khẩu." });
        }

        // Nếu mọi thứ hợp lệ -> Đăng nhập thành công
        res.status(200).json({
            message: "Đăng nhập thành công",
            user: {
                id: staffMember.id,
                name: staffMember.full_name,
                role: staffMember.primary_role
            }
        });

    } catch (error) {
        console.error("Lỗi đăng nhập:", error);
        res.status(500).json({ message: "Lỗi hệ thống Server" });
    }
});
app.get('/dashboard', (req, res) => {
    res.sendFile('E:/web_Pharmar/font_end_managements/dashboard/dashboard.html');
});


app.listen(PORT, () => {
    console.log(`Server đang chạy tại: http://localhost:${PORT}`);
});
// API Endpoint xử lý tạo tài khoản nhân viên mới
app.post('/api/staff/create', async (req, res) => {
    const {
        fullName, email, phone, role, status,
        password, forcePasswordChange
    } = req.body;

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Đã đổi 'users' thành 'staff'
        const query = `
            INSERT IGNORE INTO staff (full_name, email, phone_number, primary_role, account_status, password_hash, force_password_change)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(query, [
            fullName,
            email,
            phone || null,
            role,
            status,
            hashedPassword,
            forcePasswordChange ? 1 : 0
        ]);

        res.status(201).json({ message: "Tạo tài khoản nhân viên thành công!" });
    } catch (error) {
        res.status(500).json({ message: "Lỗi hệ thống", error });
    }
});
// đọc bảng staff để hiển thị danh sách nhân viên
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Đã đổi 'users' thành 'staff'
        const [staffMembers] = await db.promise().query('SELECT * FROM staff WHERE email = ?', [email]);

        if (staffMembers.length === 0) {
            return res.status(401).json({ message: "Email không tồn tại trong hệ thống." });
        }

        const staff = staffMembers[0];

        if (staff.account_status !== 'active') {
            return res.status(403).json({ message: "Tài khoản của bạn đã bị vô hiệu hóa." });
        }

        const isMatch = await bcrypt.compare(password, staff.password_hash);

        if (!isMatch) {
            return res.status(401).json({ message: "Sai mật khẩu." });
        }

        if (staff.force_password_change) {
            return res.status(200).json({
                message: "Yêu cầu đổi mật khẩu",
                requirePasswordChange: true
            });
        }

        res.status(200).json({
            message: "Đăng nhập thành công",
            user: { id: staff.id, name: staff.full_name, role: staff.primary_role }
        });

    } catch (error) {
        res.status(500).json({ message: "Lỗi Server" });
    }
});
// API: Lấy toàn bộ danh sách nhân viên từ bảng staff (Có hỗ trợ bộ lọc)
app.get('/api/staff', async (req, res) => {
    // Nhận dữ liệu bộ lọc từ URL do Frontend gửi lên (ví dụ: ?role=admin&status=active)
    const { role, status, search } = req.query;

    // Câu lệnh SQL gốc: Lấy các cột cần thiết, loại bỏ password_hash để bảo mật
    let query = 'SELECT id, full_name, email, phone_number, primary_role, account_status FROM staff WHERE 1=1';
    let queryParams = [];

    // Nếu Frontend có truyền lên giá trị lọc theo Vai trò (Role)
    if (role) {
        query += ' AND primary_role = ?';
        queryParams.push(role);
    }

    // Lọc chính xác theo Trạng thái (Status)
    if (status && status.trim() !== '') {
        query += ' AND account_status = ?';
        queryParams.push(status);
    }
    // 3. Thanh tìm kiếm (Tìm theo Tên, Email hoặc định dạng NV-00X)
    if (search && search.trim() !== '') {
        const searchKeyword = `%${search.trim()}%`;

        query += ' AND (full_name LIKE ? OR email LIKE ? OR id LIKE ? OR CONCAT("NV-", LPAD(id, 3, "0")) LIKE ?)';
        queryParams.push(searchKeyword, searchKeyword, searchKeyword, searchKeyword);
    }

    // Sắp xếp theo ID giảm dần (Nhân viên mới tạo lọt lên đầu bảng)
    query += ' ORDER BY id DESC';

    try {
        // Thực thi câu lệnh SQL quét database
        const [rows] = await db.promise().query(query, queryParams);

        // Trả dữ liệu mảng nhân viên về cho Frontend dưới dạng JSON
        res.status(200).json(rows);
    } catch (error) {
        console.error("Lỗi khi kết nối lấy danh sách staff:", error);
        res.status(500).json({ message: "Lỗi kết nối cơ sở dữ liệu phía máy chủ." });
    }
});
// API: Cập nhật thông tin nhân viên trực tiếp từ hàng
app.put('/api/staff/:id', async (req, res) => {
    const staffId = req.params.id;
    const { full_name, email, primary_role, phone_number, account_status } = req.body;

    // Kiểm tra dữ liệu đầu vào cơ bản
    if (!full_name || !email || !primary_role || !account_status) {
        return res.status(400).json({ message: "Vui lòng nhập đầy đủ các trường bắt buộc." });
    }

    const query = `
        UPDATE staff 
        SET full_name = ?, email = ?, primary_role = ?, phone_number = ?, account_status = ? 
        WHERE id = ?
    `;

    try {
        const [result] = await db.promise().query(query, [full_name, email, primary_role, phone_number || null, account_status, staffId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Không tìm thấy nhân viên cần sửa." });
        }

        res.status(200).json({ message: "Cập nhật thông tin nhân viên thành công!" });
    } catch (error) {
        console.error("Lỗi cập nhật nhân viên:", error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: "Email này đã được sử dụng bởi nhân viên khác." });
        }
        res.status(500).json({ message: "Lỗi hệ thống không thể lưu." });
    }
});
// ==========================================
// API QUẢN LÝ NHÀ CUNG CẤP (SUPPLIERS)
// ==========================================

// 1. API: Lấy danh sách nhà cung cấp
app.get('/api/suppliers', async (req, res) => {
    try {
        const { status, balance_filter, search } = req.query;

        let query = 'SELECT * FROM suppliers WHERE 1=1';
        let queryParams = [];

        if (status) {
            query += ' AND partnership_status = ?';
            queryParams.push(status);
        }

        if (balance_filter) {
            if (balance_filter === 'has_debt') {
                query += ' AND outstanding_balance > 0';
            } else if (balance_filter === 'clear') {
                query += ' AND outstanding_balance <= 0';
            }
        }

        if (search && search.trim() !== '') {
            const searchKeyword = `%${search.trim()}%`; // Đã sửa lại định dạng chuẩn
            query += ' AND (company_name LIKE ? OR vat_tax_id LIKE ? OR contact_email LIKE ?)';
            queryParams.push(searchKeyword, searchKeyword, searchKeyword);
        }

        query += ' ORDER BY id DESC';

        // LƯU Ý: Nếu lỗi "db.promise is not a function", hãy báo lại mình!
        const [rows] = await db.promise().query(query, queryParams);
        res.status(200).json(rows);

    } catch (error) {
        console.error("Lỗi khi lấy danh sách suppliers:", error);
        res.status(500).json({ message: "Lỗi kết nối cơ sở dữ liệu." });
    }
});
// 3. API: Cập nhật thông tin nhà cung cấp (Sửa trực tiếp)
app.put('/api/suppliers/:id', async (req, res) => {
    const supplierId = req.params.id;
    const {
        company_name, vat_tax_id, company_address,
        contact_email, phone_number, partnership_status, outstanding_balance
    } = req.body;

    const query = `
        UPDATE suppliers 
        SET company_name = ?, vat_tax_id = ?, company_address = ?, 
            contact_email = ?, phone_number = ?, partnership_status = ?, outstanding_balance = ?
        WHERE id = ?
    `;
    const params = [
        company_name, vat_tax_id, company_address, contact_email,
        phone_number, partnership_status, outstanding_balance || 0, supplierId
    ];

    try {
        const [result] = await db.promise().query(query, params);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Không tìm thấy nhà cung cấp để cập nhật." });
        }
        res.status(200).json({ message: "Cập nhật thông tin thành công!" });
    } catch (error) {
        console.error("Lỗi cập nhật supplier:", error);
        res.status(500).json({ message: "Lỗi hệ thống khi cập nhật." });
    }
});

// 4. API: Xóa nhà cung cấp
app.delete('/api/suppliers/:id', async (req, res) => {
    const supplierId = req.params.id;
    const query = 'DELETE FROM suppliers WHERE id = ?';

    try {
        const [result] = await db.promise().query(query, [supplierId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Không tìm thấy nhà cung cấp để xóa." });
        }
        res.status(200).json({ message: "Đã xóa nhà cung cấp thành công!" });
    } catch (error) {
        console.error("Lỗi xóa supplier:", error);
        res.status(500).json({ message: "Lỗi hệ thống khi xóa." });
    }
});

// 2. API: Thêm mới nhà cung cấp
app.post('/api/suppliers', async (req, res) => {
    try {
        const {
            company_name,
            vat_tax_id,
            company_address,
            contact_email,
            phone_number,
            status,
            outstanding_balance
        } = req.body;

        const query = `
            INSERT INTO suppliers 
            (company_name, vat_tax_id, company_address, contact_email, phone_number, partnership_status, outstanding_balance)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        const params = [
            company_name,
            vat_tax_id,
            company_address,
            contact_email,
            phone_number,
            status || 'active',
            outstanding_balance || 0.00
        ];

        const [result] = await db.promise().query(query, params);
        res.status(201).json({
            message: "Thêm nhà cung cấp thành công!",
            id: result.insertId
        });

    } catch (error) {
        console.error("Lỗi khi thêm supplier:", error);
        res.status(500).json({ message: "Lỗi hệ thống không thể lưu nhà cung cấp." });
    }
});