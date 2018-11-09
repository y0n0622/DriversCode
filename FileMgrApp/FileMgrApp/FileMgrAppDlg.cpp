
// FileMgrAppDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "FileMgrApp.h"
#include "FileMgrAppDlg.h"
#include "afxdialogex.h"
#include <winsvc.h>
#include <conio.h>
#include <winioctl.h>
#include <atlconv.h>

#define DRIVER_NAME L"FileDriver"
#define DRIVER_PATH L".\\FileDriver.sys"

#define IOCTRL_BASE 0x800
#define FILEIOCTRL_CODE(i) CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CTL_CREATEFILE FILEIOCTRL_CODE(0)
#define CTL_CREATEDIRECTORY FILEIOCTRL_CODE(1)
#define CTL_WRITEFILE FILEIOCTRL_CODE(2)
#define CTL_READFILE FILEIOCTRL_CODE(3)
#define CTL_COPYFILE FILEIOCTRL_CODE(4)
#define CTL_MOVEFILE FILEIOCTRL_CODE(5)
#define CTL_DELETEFILE FILEIOCTRL_CODE(6)
#define CTL_GETFILEATTRIBUTES FILEIOCTRL_CODE(7)
#define CTL_SETFILEATTRIBUTE FILEIOCTRL_CODE(8)
#define CTL_FORCEDELETEFILE FILEIOCTRL_CODE(9)




#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CFileMgrAppDlg 对话框

//加载驱动
BOOL LoadDriver(WCHAR *lpszDriverName, WCHAR *lpszDriverPath);
//卸载驱动;
BOOL UnloadDriver(WCHAR *szSeverName);


CFileMgrAppDlg::CFileMgrAppDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CFileMgrAppDlg::IDD, pParent)
	, m_filePath(_T(""))
	, m_fileCMPath(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CFileMgrAppDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_ET_PATH, m_filePath);
	DDX_Text(pDX, IDC_ET_CMPATH, m_fileCMPath);
}

BEGIN_MESSAGE_MAP(CFileMgrAppDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_GETPATH, &CFileMgrAppDlg::OnBnClickedBtnGetpath)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BTN_CREATEFILE, &CFileMgrAppDlg::OnBnClickedBtnCreatefile)
	ON_BN_CLICKED(IDC_BTN_CREATEDIRECTORY, &CFileMgrAppDlg::OnBnClickedBtnCreatedirectory)
	ON_BN_CLICKED(IDC_BTN_DELETEFILE, &CFileMgrAppDlg::OnBnClickedBtnDeletefile)
	ON_BN_CLICKED(IDC_BTN_FORCEDELFILE, &CFileMgrAppDlg::OnBnClickedBtnForcedelfile)
	ON_BN_CLICKED(IDC_BTN_WRITEFILE, &CFileMgrAppDlg::OnBnClickedBtnWritefile)
	ON_BN_CLICKED(IDC_BTN_READFILE2, &CFileMgrAppDlg::OnBnClickedBtnReadfile2)
	ON_BN_CLICKED(IDC_BTN_COPYFILE, &CFileMgrAppDlg::OnBnClickedBtnCopyfile)
	ON_BN_CLICKED(IDC_BTN_MOVEFILE, &CFileMgrAppDlg::OnBnClickedBtnMovefile)
	ON_BN_CLICKED(IDC_BTN_GETCMPATH, &CFileMgrAppDlg::OnBnClickedBtnGetcmpath)
END_MESSAGE_MAP()


// CFileMgrAppDlg 消息处理程序

BOOL CFileMgrAppDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ShowWindow(SW_MINIMIZE);

	// TODO:  在此添加额外的初始化代码
	//加载驱动
	bRet = LoadDriver(DRIVER_NAME, DRIVER_PATH);
	if (!bRet)
	{
		MessageBox(L"驱动加载失败！", L"tips", MB_OK);
		//printf("LoadNtDriver Error!\n");
	}
	else
	{
		MessageBox(L"驱动加载成功！", L"tips", MB_OK);
		//printf("LoadNtDriver ok;!\n");
	}

	//创建驱动
	hDevice = CreateFile(L"\\\\.\\FileDriver", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice != INVALID_HANDLE_VALUE)
	{
		//printf("Create Device ok;!\n");
		MessageBox(L"创建驱动句柄成功！", L"tips", MB_OK);
	}
	else
	{
		MessageBox(L"创建驱动句柄失败！", L"tips", MB_OK);
		//printf("Create Device Failed %d !\n", GetLastError());
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CFileMgrAppDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CFileMgrAppDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CFileMgrAppDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CFileMgrAppDlg::OnBnClickedBtnGetpath()
{
	// TODO:  在此添加控件通知处理程序代码
	CFileDialog ObjFile(TRUE, NULL, NULL, 0, L"所有文件|*.*|");
	if (IDOK == ObjFile.DoModal())
	{
		m_filePath = ObjFile.GetPathName();
		UpdateData(FALSE);
		if (m_filePath.IsEmpty())
		{
			MessageBox(L"路径获取失败!", L"tips", MB_OK);
		}
	}
}

void CFileMgrAppDlg::OnClose()
{
	// TODO:  在此添加消息处理程序代码和/或调用默认值
	//关闭驱动句柄
	CloseHandle(hDevice);
	bRet = UnloadDriver(DRIVER_NAME);
	if (!bRet)
	{
		//printf("UnloadNtDriver Error!\n");
		MessageBox(L"卸载驱动失败！", L"tips", MB_OK);
	}
	else
	{
		MessageBox(L"卸载驱动成功！", L"tips", MB_OK);
	}
	CDialogEx::OnClose();
}

void CFileMgrAppDlg::OnBnClickedBtnCreatefile()
{
	// TODO:  在此添加控件通知处理程序代码
	DriverFunction(CTL_CREATEFILE);
}


void CFileMgrAppDlg::OnBnClickedBtnCreatedirectory()
{
	// TODO:  在此添加控件通知处理程序代码
	DriverFunction(CTL_CREATEDIRECTORY);
}


void CFileMgrAppDlg::OnBnClickedBtnDeletefile()
{
	// TODO:  在此添加控件通知处理程序代码
	DriverFunction(CTL_DELETEFILE);
	
}


void CFileMgrAppDlg::OnBnClickedBtnForcedelfile()
{
	// TODO:  在此添加控件通知处理程序代码
	DriverFunction(CTL_FORCEDELETEFILE);
}


void CFileMgrAppDlg::OnBnClickedBtnWritefile()
{
	// TODO:  在此添加控件通知处理程序代码
	DriverFunction(CTL_WRITEFILE);
}


void CFileMgrAppDlg::OnBnClickedBtnReadfile2()
{
	// TODO:  在此添加控件通知处理程序代码
	DriverFunction(CTL_READFILE);
}

struct _PATH
{
	WCHAR bufFileSrcInput[128];
	WCHAR bufFileDstInput[128];
};
void CFileMgrAppDlg::OnBnClickedBtnCopyfile()
{
	// TODO:  在此添加控件通知处理程序代码
	UpdateData(TRUE);
	_PATH path;
	_PATH out = {0};
	path.bufFileSrcInput[128] = { 0 };
	path.bufFileDstInput[128] = { 0 };
	for (int i = 0; i < m_filePath.GetLength(); i++)
	{
		path.bufFileSrcInput[i] = (WCHAR)m_filePath.GetAt(i);
	}
	
	for (int j = 0; j < m_fileCMPath.GetLength(); j++)
	{
		path.bufFileDstInput[j] = (WCHAR)m_fileCMPath.GetAt(j);
	}
	//WCHAR bufOutput[520] = { 0 };
	DWORD dwRet = 0;
	int n = sizeof(path);
	int m = sizeof(out);
	DeviceIoControl(hDevice, CTL_COPYFILE, &path, sizeof(path), &out, sizeof(out), &dwRet, NULL);
	if (dwRet)
	{
		MessageBox(L"驱动执行成功!", L"tips", MB_OK);
	}
	else
	{
		MessageBox(L"驱动执行失败!", L"tips", MB_OK);
	}
}


void CFileMgrAppDlg::OnBnClickedBtnMovefile()
{
	// TODO:  在此添加控件通知处理程序代码
	UpdateData(TRUE);
	_PATH path = { 0 };
	_PATH out = { 0 };
	path.bufFileSrcInput[128] = { 0 };
	for (int i = 0; i < m_filePath.GetLength(); i++)
	{
		path.bufFileSrcInput[i] = (WCHAR)m_filePath.GetAt(i);
	}
	path.bufFileDstInput[128] = { 0 };
	for (int j = 0; j < m_fileCMPath.GetLength(); j++)
	{
		path.bufFileDstInput[j] = (WCHAR)m_fileCMPath.GetAt(j);
	}
	//WCHAR bufOutput[520] = { 0 };
	DWORD dwRet = 0;
	int n = sizeof(path);
	int m = sizeof(out);
	DeviceIoControl(hDevice, CTL_MOVEFILE, &path, sizeof(path), &out, sizeof(out), &dwRet, NULL);
	if (dwRet)
	{
		MessageBox(L"驱动执行成功!", L"tips", MB_OK);
	}
	else
	{
		MessageBox(L"驱动执行失败!", L"tips", MB_OK);
	}
}

void CFileMgrAppDlg::OnBnClickedBtnGetcmpath()
{
	// TODO:  在此添加控件通知处理程序代码
	CFileDialog ObjFile(TRUE, NULL, NULL, 0, L"所有文件|*.*|");
	if (IDOK == ObjFile.DoModal())
	{
		m_fileCMPath = ObjFile.GetPathName();
		UpdateData(FALSE);
		if (m_filePath.IsEmpty())
		{
			MessageBox(L"路径获取失败!", L"tips", MB_OK);
		}
	}
}

BOOL LoadDriver(WCHAR *lpszDriverName, WCHAR *lpszDriverPath)
{
	WCHAR szDriverImagePath[256] = { 0 };
	GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

	BOOL bRet = FALSE;

	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;

	//打开服务控制管理器;
	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hServiceMgr == NULL)
	{
		printf("OpenSCManager() Failed %d!\n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		//OpenSCManager成功
		printf("OpenSCManager() ok!\n");
	}

	//创建驱动对应的服务;
	hServiceDDK = CreateService(hServiceMgr, lpszDriverName, lpszDriverName,
		SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE, szDriverImagePath, NULL, NULL, NULL, NULL, NULL);

	DWORD dwRtn;
	//判断服务是否失败;
	if (hServiceDDK == NULL)
	{
		dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
		{
			//其他原因失败;
			printf("CreateService() Failed %d !\n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			//服务挂起或存在;
			printf("CreateService() Failed Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS!\n");
		}

		//驱动已经加载;
		hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
		if (hServiceDDK == NULL)
		{
			dwRtn = GetLastError();
			printf("OpenService() Failed %d!\n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			printf("OpenService() ok!\n");
		}
	}
	else
	{
		printf("CreateService() ok!\n");
	}

	//启动服务;
	bRet = StartService(hServiceDDK, NULL, NULL);
	if (!bRet)
	{
		DWORD dwRtn = GetLastError();
		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
		{
			printf("StartService() Failed %d !\n", dwRtn);
			bRet = FALSE;
			goto BeforeLeave;
		}
		else
		{
			if (dwRtn == ERROR_IO_PENDING)
			{
				printf("StartService() Failed ERROR_IO_PENDING!\n");
				bRet = FALSE;
				goto BeforeLeave;
			}
			else
			{
				printf("StartService() Failed ERROR_SERVICE_ALREADY_RUNNING!\n");
				bRet = TRUE;
				goto BeforeLeave;
			}
		}
	}
	bRet = TRUE;
BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

//卸载驱动;
BOOL UnloadDriver(WCHAR *szSeverName)
{
	BOOL bRet = FALSE;
	SC_HANDLE hServiceMgr = NULL;
	SC_HANDLE hServiceDDK = NULL;
	SERVICE_STATUS ServiceStatus;

	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hServiceMgr == NULL)
	{
		printf("OpenScManager() Fialed %d!\n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		printf("OpenSCManager() ok !\n");
	}

	hServiceDDK = OpenService(hServiceMgr, szSeverName, SERVICE_ALL_ACCESS);
	if (hServiceDDK == NULL)
	{
		printf("OpenService() Failed %d !\n", GetLastError());
		bRet = FALSE;
		goto BeforeLeave;
	}
	else
	{
		printf("OpenService() ok!\n");
	}
	//停止驱动程序，如果失败，只有重新启动才能，再动态加载;
	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &ServiceStatus))
	{
		printf("ControlService() Fialed %d !\n", GetLastError());
	}
	else
	{
		printf("ControlService() ok!\n");
	}

	//动态卸载驱动;
	if (!DeleteService(hServiceDDK))
	{
		printf("DeleteService() Fialed!\n");
	}
	else
	{
		printf("DeleteService() ok!\n");
	}
	bRet = TRUE;

BeforeLeave:
	if (hServiceDDK)
	{
		CloseServiceHandle(hServiceDDK);
	}
	if (hServiceMgr)
	{
		CloseServiceHandle(hServiceMgr);
	}
	return bRet;
}

VOID CFileMgrAppDlg::DriverFunction(int ioctrl)
{
	UpdateData(TRUE);
	WCHAR bufFileInput[512] = { 0 };
	for (int i = 0; i < m_filePath.GetLength(); i++)
	{
		bufFileInput[i] = m_filePath.GetAt(i);
	}
	WCHAR bufOutput[512] = { 0 };
	DWORD dwRet = 0;

	DeviceIoControl(hDevice, ioctrl, bufFileInput, 1024, bufOutput, 1024, &dwRet, NULL);
	if (dwRet)
	{
		MessageBox(bufOutput, L"tips", MB_OK);
	}
	else
	{
		MessageBox(L"驱动执行失败!", L"tips", MB_OK);
	}
}