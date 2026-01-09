include \masm32\include\masm32rt.inc


.data
m   dd 0 ;khai bao bien giong kieu 'int m' trong c
n   dd 0 
lo  dd 0
hi  dd 0

.code
start: ;bat dau ct
    invoke AllocConsole ;tao console de nhin
    
    ;nhap so
    mov m, sval(input("nhap so thu nhat = ")) ;input("...") nhap so vao, con sval la chuyen so do sang 32 bit, roi mov m de luu no vao m
    mov n, sval(input("nhap so thu hai = ")) 

    ;cong
    mov eax, m ;dua m vao eax
    add eax, n ;cong n vao eax, tuc eax = m + n 
    mov lo, eax ;luu eax = m + n vao lo

    mov edx, 0
    adc edx, 0        ; adc o day tuc la add + carry flag, tuc edx = eedx + 0 + CF
    mov hi, edx       ; luu hi

    ;in ket qua
    print chr$("hi = ") ;in ra 'hi='
    print str$(hi) ;in ra hi
    print chr$(13,10) ;xuong dong
    print chr$("lo = ")
    print str$(lo)
    print chr$(13,10)
    inkey ;doi nguoi dung nhap so
    
    exit ;thoat ct
    
end start ;ket thuc ct      
