import pyshark
cap = pyshark.LiveCapture('en0')
cap.sniff(timeout=20)
for c in cap:
    print(c)
    f = open("sample.txt", "a+")
    for i in range(10):
        r = str(c)
        f.write(r)
    f.close()