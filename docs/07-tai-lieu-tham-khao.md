# Chương 07 — Tài liệu tham khảo

> Danh mục nguồn dùng cho toàn bộ tài liệu, phân theo chủ đề. Ưu tiên **nguồn gốc
> học thuật** (IACR ePrint, USENIX, Springer/LNCS, IEEE, ACM, RFC, NVD/CVE) và các
> **trang dự án chính thức**. Mỗi mục ghi đủ thông tin thư mục (tác giả — tên —
> hội nghị/tạp chí, năm) để có thể trích dẫn ngay cả khi URL thay đổi.

## A. Nền tảng & tiêu chuẩn

- FIPS 186-5, *Digital Signature Standard (DSS)*, NIST, 2023.
- SEC 1, *Elliptic Curve Cryptography*, Certicom Research.
- T. Pornin, **RFC 6979** — *Deterministic Usage of DSA and ECDSA*, IETF, 2013.
  https://www.rfc-editor.org/rfc/rfc6979
- S. Josefsson, I. Liusvaara, **RFC 8032** — *Edwards-Curve Digital Signature
  Algorithm (EdDSA)*, IETF, 2017. https://www.rfc-editor.org/rfc/rfc8032

## B. Tấn công nonce, Hidden Number Problem & tấn công lưới

- D. Boneh, R. Venkatesan, *Hardness of Computing the Most Significant Bits of
  Secret Keys in Diffie-Hellman and Related Schemes*, CRYPTO 1996 (LNCS 1109).
- N. Howgrave-Graham, N. Smart, *Lattice Attacks on Digital Signature Schemes*,
  Designs, Codes and Cryptography 23(3), 2001.
  https://link.springer.com/article/10.1023/A:1011214926272
- P. Nguyen, I. Shparlinski, *The Insecurity of the Elliptic Curve Digital
  Signature Algorithm with Partially Known Nonces*, Designs, Codes and Cryptography
  30(2), 2003. https://link.springer.com/article/10.1023/A:1025436905711
- D. Bleichenbacher, *On the generation of one-time keys in DSA* (rump session,
  IEEE P1363), 2000.
- E. De Mulder, M. Hutter, M. Marson, P. Pearson, *Using Bleichenbacher's Solution
  to the Hidden Number Problem to Attack Nonce Leaks in 384-Bit ECDSA*, CHES 2013.
- J. Breitner, N. Heninger, *Biased Nonce Sense: Lattice Attacks against Weak ECDSA
  Signatures in Cryptocurrencies*, Financial Cryptography (FC) 2019 — IACR ePrint
  2019/023. https://eprint.iacr.org/2019/023
  - Blog tác giả: https://www.joachim-breitner.de/blog/749-Nonce_sense_paper_online
- Công cụ minh họa nonce reuse: https://github.com/tintinweb/ecdsa-private-key-recovery
  · https://github.com/pcaversaccio/ecdsa-nonce-reuse-attack

## C. Tấn công kênh bên (timing, cache, power, EM, fault)

- P. Kocher, *Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and
  Other Systems*, CRYPTO 1996.
- P. Kocher, J. Jaffe, B. Jun, *Differential Power Analysis*, CRYPTO 1999.
- J.-S. Coron, *Resistance against Differential Power Analysis for Elliptic Curve
  Cryptosystems*, CHES 1999.
- B. Brumley, R. Hakala, *Cache-Timing Template Attacks*, ASIACRYPT 2009.
- B. Brumley, N. Tuveri, *Remote Timing Attacks Are Still Practical*, ESORICS 2011
  — IACR ePrint 2011/232 (CVE-2011-1945). https://eprint.iacr.org/2011/232.pdf
- M. Medwed, E. Oswald, *Template Attacks on ECDSA*, WISA 2008 — IACR ePrint
  2008/081. https://eprint.iacr.org/2008/081.pdf
- N. Benger, J. van de Pol, N. Smart, Y. Yarom, *"Ooh Aah… Just a Little Bit": A
  Small Amount of Side Channel Can Go a Long Way*, CHES 2014 — IACR ePrint 2014/161.
  https://eprint.iacr.org/2014/161.pdf
- D. Genkin, L. Pachmanov, I. Pipman, E. Tromer, Y. Yarom, *ECDSA Key Extraction
  from Mobile Devices via Nonintrusive Physical Side Channels*, ACM CCS 2016 — IACR
  ePrint 2016/230. https://eprint.iacr.org/2016/230
- Y. Yarom, D. Genkin, N. Heninger, *CacheBleed: A Timing Attack on OpenSSL
  Constant-Time RSA*, CHES 2016 (CVE-2016-0702).
  https://web.eecs.umich.edu/~genkin/cachebleed/index.html
- K. Ryan, *Return of the Hidden Number Problem*, TCHES 2019(1).
  https://tches.iacr.org/index.php/TCHES/article/view/7337
- D. Naccache, P. Nguyen, M. Tunstall, C. Whelan, *Experimenting with Faults,
  Lattices and the DSA*, PKC 2005.
- J.-M. Schmidt, M. Medwed, *A Fault Attack on ECDSA*, FDTC 2009.
- Y. Romailler, S. Pelissier, *Practical Fault Attack against the Ed25519 and EdDSA
  Signature Schemes*, FDTC 2017. https://romailler.ch/ddl/10.1109_FDTC.2017.12_eddsa.pdf
- *Lattice-Based Fault Attacks on Deterministic Signature Schemes of ECDSA and
  EdDSA*, CT-RSA 2022 — IACR ePrint 2020/803. https://eprint.iacr.org/2020/803.pdf

### Tấn công có tên riêng
- J. Jancar, V. Sedláček, P. Švenda, M. Sýs, *Minerva: The curse of ECDSA nonces*,
  TCHES 2020 — IACR ePrint 2020/728. https://eprint.iacr.org/2020/728.pdf
  · Trang dự án: https://minerva.crocs.fi.muni.cz/
- D. F. Aranha, F. R. Novaes, A. Takahashi, M. Tibouchi, Y. Yarom, *LadderLeak:
  Breaking ECDSA with Less than One Bit of Nonce Leakage*, ACM CCS 2020 — IACR
  ePrint 2020/615. https://eprint.iacr.org/2020/615.pdf
- D. Moghimi, B. Sunar, T. Eisenbarth, N. Heninger, *TPM-FAIL: TPM meets Timing and
  Lattice Attacks*, USENIX Security 2020 (CVE-2019-11090, CVE-2019-16863).
  https://www.usenix.org/system/files/sec20-moghimi-tpm.pdf · https://tpm.fail/
- T. Roche, *EUCLEAK* (Infineon/YubiKey), 2024 — IACR ePrint 2024/1380.
  https://ninjalab.io/eucleak/ · https://eprint.iacr.org/2024/1380

## D. Tấn công toán học vào ECDLP & đường cong yếu

- D. Shanks, *Class number, a theory of factorization and genera* (Baby-step
  Giant-step), 1971.
- J. Pollard, *Monte Carlo methods for index computation (mod p)*, Math. Comp.,
  1978.
- P. van Oorschot, M. Wiener, *Parallel Collision Search with Cryptanalytic
  Applications*, J. Cryptology 12(1), 1999.
  https://people.scs.carleton.ca/~paulv/papers/JoC97.pdf
- S. Pohlig, M. Hellman, *An Improved Algorithm for Computing Logarithms over
  GF(p)…*, IEEE Trans. Inf. Theory, 1978.
- A. Menezes, T. Okamoto, S. Vanstone, *Reducing Elliptic Curve Logarithms to
  Logarithms in a Finite Field* (MOV attack), IEEE Trans. Inf. Theory 39(5), 1993.
- G. Frey, H.-G. Rück, *A remark concerning m-divisibility and the discrete
  logarithm in the divisor class group of curves*, Math. Comp. 62, 1994.
- N. Smart, *The Discrete Logarithm Problem on Elliptic Curves of Trace One*, J.
  Cryptology 12(3), 1999 (đồng thời: Satoh–Araki 1998; Semaev 1998).
- S. Galbraith, P. Gaudry, *Recent progress on the elliptic curve discrete
  logarithm problem*, IACR ePrint 2015/1022. https://eprint.iacr.org/2015/1022.pdf
- D. Bailey và cộng sự, *Breaking ECC2K-130*, IACR ePrint 2009/541.
  https://eprint.iacr.org/2009/541.pdf
- C. Novotney, *Weak Curves in Elliptic Curve Cryptography*, 2010.
  https://wstein.org/edu/2010/414/projects/novotney.pdf

### Invalid curve / twist / small subgroup
- I. Biehl, B. Meyer, V. Müller, *Differential Fault Attacks on Elliptic Curve
  Cryptosystems*, CRYPTO 2000.
- A. Antipa, D. Brown, A. Menezes, R. Struik, S. Vanstone, *Validation of Elliptic
  Curve Public Keys*, PKC 2003. https://iacr.org/archive/pkc2003/25670211/25670211.pdf
- T. Jager, J. Schwenk, J. Somorovsky, *Practical Invalid Curve Attacks on
  TLS-ECDH*, **ESORICS 2015**. https://www.nds.rub.de/research/publications/ESORICS15/
- C. Lim, P. Lee, *A key recovery attack on discrete log-based schemes using a
  prime order subgroup*, CRYPTO 1997.
- L. Valenta và cộng sự, *Measuring Small Subgroup Attacks against Diffie-Hellman*,
  NDSS 2017.
  https://www.ndss-symposium.org/wp-content/uploads/2017/09/ndss2017_04A-1_Valenta_paper_0.pdf

## E. Lỗi triển khai (Psychic Signatures, malleability, validation)

- N. Madden, *Psychic Signatures in Java* (CVE-2022-21449), 2022.
  https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
  · NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-21449
  · JFrog: https://jfrog.com/blog/cve-2022-21449-psychic-signatures-analyzing-the-new-java-crypto-vulnerability/
- C. Decker, R. Wattenhofer, *Bitcoin Transaction Malleability and MtGox*, ESORICS
  2014.
- BIP-62 (*Dealing with malleability*):
  https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- BIP-146 (*Dealing with signature encoding malleability*):
  https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
- CurveBall (CVE-2020-0601): https://nvd.nist.gov/vuln/detail/CVE-2020-0601
- Ma trận / libolm deprecation (2024): https://matrix.org/blog/2024/08/libolm-deprecation/
  · Công bố CVE-2024-45191/45192/45193 (Soatok):
  https://gist.github.com/soatok/0a3d24710b2ccac2aac14820008b06ab

## F. Cửa hậu tham số & đường cong minh bạch

- D. Shumow, N. Ferguson, *On the Possibility of a Back Door in the NIST SP800-90
  Dual Ec Prng* (rump session CRYPTO 2007).
- S. Checkoway và cộng sự, *On the Practical Exploitability of Dual EC in TLS
  Implementations*, USENIX Security 2014.
- S. Checkoway và cộng sự, *A Systematic Analysis of the Juniper Dual EC Incident*,
  ACM CCS 2016 — IACR ePrint 2016/376 (CVE-2015-7755/7756).
  https://eprint.iacr.org/2016/376.pdf
  · M. Green, *On the Juniper backdoor*:
  https://blog.cryptographyengineering.com/2015/12/22/on-juniper-backdoor/
- D. J. Bernstein, *Curve25519: new Diffie-Hellman speed records*, PKC 2006.
  https://cr.yp.to/ecdh.html
- D. J. Bernstein, T. Lange, *SafeCurves: choosing safe curves for elliptic-curve
  cryptography*. https://safecurves.cr.yp.to

## G. Sự cố thực tế & tài nguyên khác

- fail0verflow, *Console Hacking 2010 — PS3 Epic Fail*, 27C3, 2010.
- Cảnh báo Bitcoin/Android (CVE-2013-7372): https://bitcoin.org/en/alert/2013-08-11-android
  · NVD: https://nvd.nist.gov/vuln/detail/CVE-2013-7372
- T. Roche, V. Lomné, *A Side Journey to Titan* (Google Titan clone), NinjaLab 2021.

## H. Mật mã hậu lượng tử (đối phó dài hạn)

- P. Shor, *Polynomial-Time Algorithms for Prime Factorization and Discrete
  Logarithms on a Quantum Computer*, SIAM J. Computing, 1997.
- NIST **FIPS 204** — *Module-Lattice-Based Digital Signature Standard (ML-DSA)*, 2024.
- NIST **FIPS 205** — *Stateless Hash-Based Digital Signature Standard (SLH-DSA)*, 2024.

---

### Ghi chú về độ tin cậy nguồn
- Các mục thuộc **IACR ePrint, USENIX, Springer/LNCS, IEEE, ACM, RFC, NVD** là nguồn
  học thuật/chính thức — nên dùng làm **căn cứ trích dẫn chính**.
- Các liên kết **blog cá nhân / trang dự án** (neilmadden.blog, tpm.fail,
  ninjalab.io, safecurves…) là nguồn gốc đáng tin của chính tác giả/nhóm phát hiện,
  dùng tốt để minh họa và tra cứu chi tiết kỹ thuật.
- Vài chi tiết định lượng (số chữ ký cần thiết, số BTC thiệt hại, số quan sát) nên
  **đối chiếu lại bản PDF gốc** khi đưa vào báo cáo nộp, vì các con số này đôi khi
  khác nhau giữa bản tóm tắt và bản đầy đủ.
