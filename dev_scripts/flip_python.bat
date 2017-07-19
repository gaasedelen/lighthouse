
if exist C:\Python27_32 (
    MOVE C:\Python27 C:\Python27_64
    MOVE C:\Python27_32 C:\Python27
) else (
    MOVE C:\Python27 C:\Python27_32
    MOVE C:\Python27_64 C:\Python27
)