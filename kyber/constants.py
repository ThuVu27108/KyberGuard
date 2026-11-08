
# all of these values are percisely defined in the official Kyber specification document

n = 256
"""

Plaintext size in bits. - Kích thước của plaintext theo bit.
Bậc của đa thức được sử dụng trong Kyber, làm tham số nền tảng và cố định cho mọi phiên bản.
"""


q = 3329
"""
Divider of polynomial coefficient modulos. - Số chia cho phép toán modulo của các hệ số đa thức
Là modulus của các phép tính, mọi hệ số của đa thức đều là số nguyên trong khoảng từ 0 đến q-1.
"""


k = 4
"""
Dimension of polynomial matrices. - Số chiều của các ma trận đa thức.
Higher values mean improved security. - Giá trị cao hơn tức là độ bảo mật được cải thiện.
Value `4` is specifically for Kyber1024 variant. - 4 là giá trị dành riêng cho Kyber1024.
Kyber làm việc với véc tơ và các ma trận k x k của các đa thức => k càng lớn, bài toán càng khó giải => độ bảo mật càng cao.
"""


eta1 = 2
"""
Defines noise level for some polynomials. - Mức độ nhiễu cho một số đa thức.
Value `2` is specifically for Kyber1024 variant. - 2 là giá trị dành riêng cho Kyber1024.
"""


eta2 = 2
"""
Defines noise level for some polynomials.
Value `2` is specifically for Kyber1024 variant.
"""


du = 11
"""
Specifies compression and encoding level for some polynomials. - Mức độ nén và mã hóa cho một số đa thức.
Value `11` is specifically for Kyber1024 variant.
Tham số nén. Để giảm kích thước của khóa công khai và bản mã, Kyber giảm số bit dùng để biểu diễn mỗi hệ số, du = 11 là mỗi hệ số trong u được nén xuống còn 11 bit.
"""


dv = 5
"""
Specifies compression and encoding level for some polynomials.
Value `5` is specifically for Kyber1024 variant.
"""
