
// AES UI ToolsDlg.cpp : implementation file
//

#include "stdafx.h"
#include "AES UI Tools.h"
#include "AES UI ToolsDlg.h"
#include "afxdialogex.h"
#include "aes.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAESUIToolsDlg dialog




CAESUIToolsDlg::CAESUIToolsDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CAESUIToolsDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAESUIToolsDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_Key, m_Key);
    DDX_Control(pDX, IDC_InitVector, m_InitVector);
    DDX_Control(pDX, IDC_Data, m_Data);
    DDX_Control(pDX, IDC_Result, m_Result);
    DDX_Control(pDX, IDC_SResult, m_SResult);
}

BEGIN_MESSAGE_MAP(CAESUIToolsDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON1, &CAESUIToolsDlg::OnBnClickedButton1)
    ON_BN_CLICKED(IDC_Enc_CBC, &CAESUIToolsDlg::OnBnClickedEncCbc)
    ON_BN_CLICKED(IDC_Dec_CBC, &CAESUIToolsDlg::OnBnClickedDecCbc)
    ON_BN_CLICKED(IDC_Enc_EBC, &CAESUIToolsDlg::OnBnClickedEncEbc)
    ON_BN_CLICKED(IDC_Dec_EBC, &CAESUIToolsDlg::OnBnClickedDecEbc)
    ON_BN_CLICKED(IDC_Count_CMAC, &CAESUIToolsDlg::OnBnClickedCountCmac)
END_MESSAGE_MAP()


// CAESUIToolsDlg message handlers

BOOL CAESUIToolsDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CAESUIToolsDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CAESUIToolsDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CAESUIToolsDlg::CStoUnChar(CString DataIn,BYTE *DataOut, int LengthIn)
{
    BYTE *BufCh1;
    BufCh1 = new BYTE[DataIn.GetLength()];
    BufCh1 = (BYTE *)(LPCTSTR) DataIn;

    BYTE BufCh2[333];
    for(int i=0; i<LengthIn; i++)
    {
        switch(BufCh1[i])
        {
            case 0x30: BufCh2[i] = 0x0;break;
            case 0x31: BufCh2[i] = 0x1;break;
            case 0x32: BufCh2[i] = 0x2;break;
            case 0x33: BufCh2[i] = 0x3;break;
            case 0x34: BufCh2[i] = 0x4;break;
            case 0x35: BufCh2[i] = 0x5;break;
            case 0x36: BufCh2[i] = 0x6;break;
            case 0x37: BufCh2[i] = 0x7;break;
            case 0x38: BufCh2[i] = 0x8;break;
            case 0x39: BufCh2[i] = 0x9;break;
            case 0x41: BufCh2[i] = 0xa;break;
            case 0x42: BufCh2[i] = 0xb;break;
            case 0x43: BufCh2[i] = 0xc;break;
            case 0x44: BufCh2[i] = 0xd;break;
            case 0x45: BufCh2[i] = 0xe;break;
            case 0x46: BufCh2[i] = 0xf;break;
            case 0x61: BufCh2[i] = 0xa;break;
            case 0x62: BufCh2[i] = 0xb;break;
            case 0x63: BufCh2[i] = 0xc;break;
            case 0x64: BufCh2[i] = 0xd;break;
            case 0x65: BufCh2[i] = 0xe;break;
            case 0x66: BufCh2[i] = 0xf;break;
            default: BufCh2[i] = 0x0;
        }              
                          
    }  

    int IndeksOut;
    if((LengthIn%2) == 0 )
    {
        IndeksOut = LengthIn/2;
    }else
    {
        
        IndeksOut = (LengthIn/2) + 1;
        BufCh2[LengthIn] = 0x00;
    }


    DataOut[0] = ((BufCh2[0]<<4)&0xF0)|BufCh2[1]&0x0F;
    for(int i=1; i<IndeksOut; i++)
    {
        DataOut[i]=((BufCh2[i*2]<<4)&0xF0)|(BufCh2[i*2+1]&0x0F);
    }

}

void CAESUIToolsDlg::OnBnClickedButton1()
{
    CString temp;
    m_Key.GetWindowText(CSKey);
    CSKey.TrimLeft(); CSKey.TrimRight(); CSKey.Replace(" ","");
    m_InitVector.GetWindowText(CSInitVector);
    CSInitVector.TrimLeft(); CSInitVector.TrimRight(); CSInitVector.Replace(" ","");
    m_Data.GetWindowText(CSDataRaw);
    CSDataRaw.TrimLeft(); CSDataRaw.TrimRight(); CSDataRaw.Replace(" ","");
   

    

    temp.Append("Key : \r\n"+CSKey+"\r\n");
    temp.Append("InitVector : \r\n"+CSInitVector+"\r\n");    
    temp.Append("Data : \r\n"+CSDataRaw+"\r\n");
    m_Result.SetWindowText(temp);
    m_SResult.SetWindowText(" Data Yang Dimasukkan : ");
}


void CAESUIToolsDlg::OnBnClickedEncCbc()
{
    BYTE Key[16];
    BYTE InitVect[16];
    BYTE Data[16*34];
    BYTE Result[16*34];
    //BYTE Segment;

    CStoUnChar(CSKey,Key,32);
    CStoUnChar(CSInitVector,InitVect,32);

    int L,Length;
    L = CSDataRaw.GetLength();
    if((L%2) == 0)//genep
    {
        Length = L/2;
    }else
    {
        Length = L/2 + 1;
    }

    CStoUnChar(CSDataRaw,Data,L); 
    AES128 m_aes128;

    memcpy(m_aes128.aeskey,Key,16);
    memcpy(m_aes128.initvector,InitVect,16);

    m_aes128.p_input = Data;
    m_aes128.inlength = Length;
    m_aes128.aes_mode = AES_MODE_CBC;
    m_aes128.p_output = Result;
    m_aes128.outlength = Length;
    aes128_encipher(&m_aes128);

    int i=1;
    CString temp,CSResult;
    for(int j=0; j<Length; j++)
    {
        temp.Format("%02X",Result[j]);
        CSResult.Append(temp);
        if(j == ((16*i)-1) )
        {
            CSResult.Append("\r\n");
            i++;
        }
    }

    m_SResult.SetWindowText("Hasil Enc-CBC : ");
    m_Result.SetWindowText(CSResult);
}


void CAESUIToolsDlg::OnBnClickedDecCbc()
{
    BYTE Key[16];
    BYTE InitVect[16];
    BYTE Data[16*23];
    BYTE Result[16*23];

    CStoUnChar(CSKey,Key,32);
    CStoUnChar(CSInitVector,InitVect,32);

    int L,Length;
    L = CSDataRaw.GetLength();
    if((L%2) == 0)//genep
    {
        Length = L/2;
    }else
    {
        Length = L/2 + 1;
    }

    CStoUnChar(CSDataRaw,Data,L);
    AES128 m_AES128;

    memcpy(m_AES128.aeskey,Key,16);
    memcpy(m_AES128.initvector,InitVect,16);

    m_AES128.p_input = &Data[0];
    m_AES128.inlength = Length;
    m_AES128.aes_mode = AES_MODE_CBC;
    m_AES128.p_output = Result;
    m_AES128.outlength = Length;

    aes128_decipher(&m_AES128);
    int i=1;
    CString temp,CSResult;
    for(int j=0; j<Length; j++)
    {
        temp.Format("%02X",Result[j]);
        CSResult.Append(temp);
        if(j == ((16*i)-1) )
        {
            CSResult.Append("\r\n");
            i++;
        }
    }

    m_SResult.SetWindowText("Hasil Dec-CBC : ");
    m_Result.SetWindowText(CSResult);
}


void CAESUIToolsDlg::OnBnClickedEncEbc()
{
    BYTE Key[16];    
    BYTE Data[16*23];
    BYTE Result[16*23];

    CStoUnChar(CSKey,Key,32);

    int L,Length;
    L = CSDataRaw.GetLength();
    if((L%2) == 0)//genep
    {
        Length = L/2;
    }else
    {
        Length = L/2 + 1;
    }

    CStoUnChar(CSDataRaw,Data,L);

    AES128 m_AES128;

    memcpy(m_AES128.aeskey,Key,16);
    m_AES128.p_input = &Data[0];
    m_AES128.inlength = Length;
    m_AES128.aes_mode = AES_MODE_ECB;
    m_AES128.p_output = Result;
    m_AES128.outlength = sizeof(Result);
    
    aes128_encipher(&m_AES128);

    int i=1;
    CString temp,CSResult;
    for(int j=0; j<Length; j++)
    {
        temp.Format("%02X",Result[j]);
        CSResult.Append(temp);
        if(j == ((16*i)-1) )
        {
            CSResult.Append("\r\n");
            i++;
        }
    }

    m_SResult.SetWindowText("Hasil Enc-ECB : ");
    m_Result.SetWindowText(CSResult);

}


void CAESUIToolsDlg::OnBnClickedDecEbc()
{
    BYTE Key[16];    
    BYTE Data[16*23];
    BYTE Result[16*23];
    CStoUnChar(CSKey,Key,32);

    int L,Length;
    L = CSDataRaw.GetLength();
    if((L%2) == 0)//genep
    {
        Length = L/2;
    }else
    {
        Length = L/2 + 1;
    }

    CStoUnChar(CSDataRaw,Data,L);

    AES128 m_AES128;
    memcpy(m_AES128.aeskey,Key,16);
    m_AES128.p_input = &Data[0];
    if(Length < 16)
    {
        m_AES128.inlength = 16;
    }else
    {
        m_AES128.inlength = Length;
    }

    m_AES128.aes_mode = AES_MODE_ECB;
    m_AES128.p_output = Result;
    m_AES128.outlength = sizeof(Result);
    
    aes128_decipher(&m_AES128);
    int i=1;
    CString temp,CSResult;
    for(int j=0; j<Length; j++)
    {
        temp.Format("%02X",Result[j]);
        CSResult.Append(temp);
        if(j == ((16*i)-1) )
        {
            CSResult.Append("\r\n");
            i++;
        }
    }

    m_SResult.SetWindowText("Hasil Dec-ECB : ");
    m_Result.SetWindowText(CSResult);
}


void CAESUIToolsDlg::OnBnClickedCountCmac()
{
    BYTE Key[16];  
    BYTE InitVector[16];
    BYTE Data[16*23];
    BYTE Result[16];
    int InitVectInt[16];

    CStoUnChar(CSKey,Key,32);
    CStoUnChar(CSInitVector,InitVector,32);

    AES128 m_AES128;

     for(int j=0;j<16;j++)
        {
            TRACE("InitVector[%i] : %X",j,InitVector[j]);
            InitVectInt[j] = InitVector[j];
            memset(&m_AES128.initvector[j],InitVector[j],sizeof(BYTE));
            TRACE("--last[%i] : %X\n",j,m_AES128.initvector[j]);
        }

    int L,Length;
    L = CSDataRaw.GetLength();
    if((L%2) == 0)//genep
    {
        Length = L/2;
    }else
    {
        Length = L/2 + 1;
    }

    CStoUnChar(CSDataRaw,Data,L);
    memcpy(m_AES128.aeskey,Key,16);//input key
    m_AES128.p_output = Result;
    m_AES128.outlength = sizeof(Result);
    
    m_AES128.p_input = &Data[0];
    m_AES128.inlength = Length;

    aescmac_generate(&m_AES128);

    int i=1;
    CString temp,CSResult;
    for(int j=0; j<16; j++)
    {
        temp.Format("%02X",Result[j]);
        CSResult.Append(temp);
        if(j == ((16*i)-1) )
        {
            CSResult.Append("\r\n");
            i++;
        }
    }

    m_SResult.SetWindowText("Hasil CMAC : ");
    m_Result.SetWindowText(CSResult);
}
