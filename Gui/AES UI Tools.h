
// AES UI Tools.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CAESUIToolsApp:
// See AES UI Tools.cpp for the implementation of this class
//

class CAESUIToolsApp : public CWinApp
{
public:
	CAESUIToolsApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CAESUIToolsApp theApp;