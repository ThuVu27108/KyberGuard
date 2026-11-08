import argparse
from base64 import b64encode
from kyber.ccakem import ccakem_generate_keys, ccakem_encrypt, ccakem_decrypt
from kyber.constants import k, n

class CLI:
    def __init__(self) -> None:
        self._parser = argparse.ArgumentParser()
        subparsers = self._parser.add_subparsers(title="command", required=True)

        keygen_parser = subparsers.add_parser("keygen")
        keygen_parser.set_defaults(command="keygen")
        keygen_parser.add_argument("outfile")

        pubkey_parser = subparsers.add_parser("pubkey", description="extract public key from private key")
        pubkey_parser.set_defaults(command="pubkey")
        pubkey_parser.add_argument("privkeyfile", help="file that contains the private key")
        pubkey_parser.add_argument("--output", "-o", metavar="FILE", help="file to write the public key (default: stdout)")

        encrypt_parser = subparsers.add_parser("encrypt", description="encrypt 32-byte random shared secret")
        encrypt_parser.set_defaults(command="encrypt")
        encrypt_parser.add_argument("--key", "-k", metavar="FILE", help="file that contains public key", required=True)
        encrypt_parser.add_argument("--secret", "-s", metavar="FILE", help="file to write the shared secret", required=True)
        encrypt_parser.add_argument("--cipher", "-c", metavar="FILE", help="file to write the ciphertext (default: stdout)")

        decrypt_parser = subparsers.add_parser("decrypt", description="decrypt 32-byte shared secret from ciphertext")
        decrypt_parser.set_defaults(command="decrypt")
        decrypt_parser.add_argument("--key", "-k", metavar="FILE", help="file that contains private key", required=True)
        decrypt_parser.add_argument("--output", "-o", metavar="FILE", help="file to write the shared secret (default: stdout)")
        decrypt_parser.add_argument("cipherfile", help="file that contains the ciphertext")

    def parse(self) -> None:
        args = self._parser.parse_args()
        handlers = {
            "keygen": self._handle_keygen,
            "pubkey": self._handle_pubkey,
            "encrypt": self._handle_encrypt,
            "decrypt": self._handle_decrypt,
        }
        handlers[args.command](args)

    def _handle_keygen(self, arguments) -> None:
        private_key, _ = ccakem_generate_keys()
        with open(arguments.outfile, "wb") as file:
            file.write(private_key)

    def _handle_pubkey(self, arguments) -> None:
        with open(arguments.privkeyfile, "rb") as file:
            private_key = file.read()
        public_key = private_key[12*k*n//8 : 24*k*n//8+32]
        if arguments.output is None:
            print(b64encode(public_key).decode("utf-8"))
        else:
            with open(arguments.output, "wb") as file:
                file.write(public_key)

    def _handle_encrypt(self, arguments) -> None:
        with open(arguments.key, "rb") as file:
            public_key = file.read()
        ciphertext, shared_secret = ccakem_encrypt(public_key)
        with open(arguments.secret, "wb") as file:
            file.write(shared_secret)
        if arguments.cipher is None:
            print(b64encode(ciphertext).decode("utf-8"))
        else:
            with open(arguments.cipher, "wb") as file:
                file.write(ciphertext)

    def _handle_decrypt(self, arguments) -> None:
        with open(arguments.key, "rb") as file:
            private_key = file.read()
        with open(arguments.cipherfile, "rb") as file:
            ciphertext = file.read()
        shared_secret = ccakem_decrypt(ciphertext, private_key)
        if arguments.output is None:
            print(b64encode(shared_secret).decode("utf-8"))
        else:
            with open(arguments.output, "wb") as file:
                file.write(shared_secret)

if __name__ == "__main__":
    CLI().parse()

'''
1. Các thư viện được import
    argparse: Đây là thư viện tiêu chuẩn của Python, và là "trái tim" của file này. Nó chuyên dùng để phân tích các đối số (arguments) và tùy chọn (options) mà người dùng gõ vào dòng lệnh.
    base64: Dùng để mã hóa dữ liệu nhị phân (binary data) thành dạng văn bản an toàn (chỉ chứa các ký tự ASCII). Điều này cần thiết khi bạn muốn in một khóa hoặc một bản mã ra màn hình terminal, vì terminal chỉ hiển thị được văn bản.
    from kyber.ccakem import ...: Đây là phần quan trọng nhất, nó import các hàm mã hóa thực sự từ thư viện kyber. cli.py chỉ gọi các hàm này mà thôi.
    from kyber.constants import k, n: Import các hằng số toán học của thuật toán Kyber.
2. class CLI và hàm __init__(self) - Định nghĩa "Menu" Lệnh
Hàm __init__ này giống như việc bạn thiết kế một cái "menu" cho chương trình của mình. Nó định nghĩa tất cả các lệnh mà người dùng có thể sử dụng.
    self._parser = argparse.ArgumentParser(): Tạo ra đối tượng phân tích cú pháp chính.
    subparsers = self._parser.add_subparsers(...): Dòng này cho argparse biết rằng chương trình của bạn sẽ có các lệnh con (subcommands) như git commit, git push.
    Định nghĩa lệnh keygen:
        keygen_parser = subparsers.add_parser("keygen"): Tạo ra một trình phân tích cú pháp riêng cho lệnh keygen.
        keygen_parser.add_argument("outfile"): Định nghĩa rằng lệnh keygen bắt buộc phải có một đối số đi kèm (tên file để lưu khóa).
    Định nghĩa lệnh pubkey:
        Tương tự, nó định nghĩa lệnh pubkey.
        pubkey_parser.add_argument("privkeyfile", ...): Yêu cầu một đối số là file khóa riêng tư.
        pubkey_parser.add_argument("--output", "-o", ...): Định nghĩa một tùy chọn (option) tên là --output (hoặc viết tắt là -o). Đây là tùy chọn không bắt buộc.
    Định nghĩa lệnh encrypt và decrypt: Cấu trúc tương tự, định nghĩa các tùy chọn bắt buộc (required=True) như --key và các tùy chọn không bắt buộc như --cipher.
3. Hàm parse(self) - Bộ điều phối
Hàm này là bộ não điều phối toàn bộ quá trình.
    args = self._parser.parse_args(): Dòng này bảo argparse: "Hãy đọc những gì người dùng đã gõ trong terminal và phân tích nó dựa trên các quy tắc mà tôi đã định nghĩa trong __init__". Kết quả được lưu vào biến args.
    handlers = {...}: Đây là một cách làm rất hay. Nó tạo ra một từ điển (dictionary) để ánh xạ tên của mỗi lệnh ("keygen", "pubkey",...) tới hàm Python tương ứng sẽ xử lý lệnh đó (self._handle_keygen, self._handle_pubkey,...).
    handlers[args.command](args): Dòng này lấy ra đúng hàm xử lý từ từ điển và gọi nó, truyền vào các đối số args đã được phân tích. Ví dụ, nếu bạn gõ keygen, nó sẽ gọi self._handle_keygen(args).
4. Các hàm _handle_... - "Công nhân" thực thi
Đây là nơi công việc thực sự được hoàn thành. Mỗi hàm tương ứng với một lệnh con.
    _handle_keygen(self, arguments):
        Gọi hàm mã hóa thực sự: private_key, _ = ccakem_generate_keys().
        Mở file mà người dùng đã chỉ định (arguments.outfile) ở chế độ ghi nhị phân ("wb"). Điều này rất quan trọng vì khóa là dữ liệu nhị phân, không phải văn bản.
        Ghi khóa riêng tư vào file.
    _handle_pubkey(self, arguments):
        Đọc file khóa riêng tư ở chế độ đọc nhị phân ("rb").
        public_key = private_key[...]: Dòng này thực hiện một phép "cắt lát" (slicing) trên dữ liệu nhị phân để trích xuất ra phần khóa công khai. (Trong Kyber, file khóa riêng tư thực chất chứa cả khóa công khai bên trong nó).
        Logic quan trọng: if arguments.output is None:
            Nếu người dùng không cung cấp tùy chọn -o (output), chương trình sẽ mã hóa khóa công khai bằng base64 và print nó ra màn hình.
            Nếu người dùng có cung cấp -o, chương trình sẽ ghi khóa công khai (dưới dạng nhị phân) vào file đó.
_handle_encrypt và _handle_decrypt:
Chúng hoạt động theo một logic hoàn toàn tương tự: đọc các file key/ciphertext cần thiết, gọi hàm mã hóa/giải mã tương ứng, và sau đó ghi kết quả vào file hoặc in ra màn hình nếu không có file output được chỉ định.
5. if __name__ == "__main__": - Điểm khởi đầu
Đây là một cấu trúc tiêu chuẩn trong Python. Nó có nghĩa là: "Nếu file này được chạy trực tiếp (bằng lệnh python cli.py), thì hãy thực thi đoạn mã bên dưới".
    CLI().parse(): Dòng này tạo một đối tượng mới từ lớp CLI và ngay lập tức gọi phương thức .parse() của nó, khởi động toàn bộ quá trình.'''