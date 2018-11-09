#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>

//#include <WTypes.h>
void StartHookShadow (void);
void RemoveHookShadow (void);


typedef BOOL (NTAPI *REAL_NtGdiStretchBlt)//293
	(
	IN HDC   hdcDst,
	IN int   xDst,
	IN int   yDst,
	IN int   cxDst,
	IN int   cyDst,
	IN HDC   hdcSrc,
	IN int   xSrc,
	IN int   ySrc,
	IN int   cxSrc,
	IN int   cySrc,
	IN DWORD dwRop,
	IN DWORD dwBackColor
	);

BOOL NTAPI HOOK_NtGdiStretchBlt//293
	(
	IN HDC   hdcDst,
	IN int   xDst,
	IN int   yDst,
	IN int   cxDst,
	IN int   cyDst,
	IN HDC   hdcSrc,
	IN int   xSrc,
	IN int   ySrc,
	IN int   cxSrc,
	IN int   cySrc,
	IN DWORD dwRop,
	IN DWORD dwBackColor
	);

typedef  BOOL (NTAPI *REAL_NtGdiBitBlt)//14
	(
	IN HDC    hdcDst,
	IN int    x,
	IN int    y,
	IN int    cx,
	IN int    cy,
	IN HDC    hdcSrc,
	IN int    xSrc,
	IN int    ySrc,
	IN DWORD  rop4,
	IN DWORD  crBackColor,
	IN FLONG  fl
	);

BOOL NTAPI HOOK_NtGdiBitBlt//14
	(
	IN HDC    hdcDst,
	IN int    x,
	IN int    y,
	IN int    cx,
	IN int    cy,
	IN HDC    hdcSrc,
	IN int    xSrc,
	IN int    ySrc,
	IN DWORD  rop4,
	IN DWORD  crBackColor,
	IN FLONG  fl
	);
