
// AES UI ToolsDlg.h : header file
//

#pragma once
#include "afxwin.h"


// CAESUIToolsDlg dialog
class CAESUIToolsDlg : public CDialogEx
{
// Construction
public:
	CAESUIToolsDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_AESUITOOLS_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
    CEdit m_Key;
    CEdit m_InitVector;
    CEdit m_Data;
    CEdit m_Result;

    CString CSKey;
    CString CSInitVector;
    CString CSData;
    CString CSSegment;
    CString CSDataRaw;
public:
    void CStoUnChar(CString DataIn,BYTE *DataOut, int LengthIn);
    afx_msg void OnBnClickedButton1();
    CStatic m_SResult;
    afx_msg void OnBnClickedEncCbc();
    afx_msg void OnBnClickedDecCbc();
    afx_msg void OnBnClickedEncEbc();
    afx_msg void OnBnClickedDecEbc();
    afx_msg void OnBnClickedCountCmac();
};
