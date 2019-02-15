#include "header.h"
#include <gdiplus.h>

using namespace Gdiplus;
#pragma comment( lib, "gdiplus.lib" )

wchar_t* charToWChar(const char* text) {
	size_t size = strlen(text) + 1;
	wchar_t* wa = new wchar_t[size];
	mbstowcs(wa, text, size);
	return wa;
}

void process_bmp(wchar_t *wcstring) {
	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	Image *image = NULL, *thumbnail = NULL;

	image = new Image(wcstring);
	if (image && (Ok == image->GetLastStatus())) {
	}
	//printf("Done\n");

	if (image) delete image;
	if (thumbnail) delete thumbnail;

	GdiplusShutdown(gdiplusToken);
}

void process_emf(wchar_t *wcstring) {

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	Bitmap* image = new Bitmap(wcstring);
	unsigned int wMax = image->GetWidth();
	unsigned int hMax = image->GetHeight();
	printf("The width of the image is %u.\n", wMax);
	printf("The height of the image is %u.\n", hMax);

	PixelFormat pixelFormat1 = image->GetPixelFormat();
	printf("The pixel format of the image is %u.\n", pixelFormat1);

	Color pixelColor;
	image->GetPixel(0, 0, &pixelColor);
	printf("Pixel (%u, %u) is color %x.\n", 0, 0, pixelColor.GetValue());  // ARGB value

	delete image;
	GdiplusShutdown(gdiplusToken);
}

INT main(INT argc, CHAR* argv[])
{
	INIT();

	if (argc != 2) PFATAL("test_gdiplus.exe [.emf|.bmp]");

	wchar_t * wcstring = charToWChar(argv[1]);
	

	while (PERSISTENT_COUNT--) {
		PRE();
		process_bmp(wcstring);
		POST();
	}

	return 0;
}
