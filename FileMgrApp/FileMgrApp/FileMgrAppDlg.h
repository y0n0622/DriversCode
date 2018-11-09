
// FileMgrAppDlg.h : 头文件
//

#pragma once


// CFileMgrAppDlg 对话框
class CFileMgrAppDlg : public CDialogEx
{
// 构造
public:
	CFileMgrAppDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_FILEMGRAPP_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnGetpath();
	CString m_filePath;
	afx_msg void OnClose();


public:
	BOOL bRet;
	HANDLE hDevice;
	VOID DriverFunction(int ioctrl);
	afx_msg void OnBnClickedBtnCreatefile();
	afx_msg void OnBnClickedBtnCreatedirectory();
	afx_msg void OnBnClickedBtnDeletefile();
	afx_msg void OnBnClickedBtnForcedelfile();
	afx_msg void OnBnClickedBtnWritefile();
	afx_msg void OnBnClickedBtnReadfile2();
	afx_msg void OnBnClickedBtnCopyfile();
	afx_msg void OnBnClickedBtnMovefile();
	CString m_fileCMPath;
	afx_msg void OnBnClickedBtnGetcmpath();
};
