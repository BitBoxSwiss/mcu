/*

 Copyright (c) 2015 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/



#include <string.h>
#include <stdio.h>
#include "sd.h"
#include "commander.h"
#ifndef TESTING
#include "mcu.h"

uint32_t sd_update = 0;
uint32_t sd_fs_found = 0;
uint32_t sd_listing_pos = 0;
uint32_t sd_num_files = 0;

FATFS fs;

#endif



/*

void display_sd_files(void)
{

	// Initialize SD MMC stack 
	sd_mmc_init();
	sd_listing_pos = 0;

	// Is SD card present?
	if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
		fill_report("sd debug", "Please insert SD card.", ERROR);
	}
	else
	{
		
		FRESULT res;
		FILINFO fno;
		DIR dir;
		uint32_t line;
		uint32_t pos;
		char *pc_fn;
		const char *path = "0:";
	#if _USE_LFN
		char c_lfn[_MAX_LFN + 1];
		fno.lfname = c_lfn;
		fno.lfsize = sizeof(c_lfn);
	#endif


		// Mount disk
		memset(&fs, 0, sizeof(FATFS));
		res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
		if (FR_INVALID_DRIVE == res) {
			fill_report("sd debug", "Failed to mount.", ERROR);
			//strcat(hid_report,"Failed to mount: res %d\r\n");
			//strcat(hid_report,(char *)res);
			return;
		}

		char files[1028] = {0};
		strcat(files,"SD card files:\n");

	
		line = 0;
		pos = 1;

		// Open the directory 
		res = f_opendir(&dir, path);
		if (res == FR_OK)
		{
			for (;;)
			{
				res = f_readdir(&dir, &fno);
				if (res != FR_OK || fno.fname[0] == 0)
				{
					break;
				}

	#if _USE_LFN
				pc_fn = *fno.lfname ? fno.lfname : fno.fname;
	#else
				pc_fn = fno.fname;
	#endif
				if (*pc_fn == '.')
				{
					continue;
				}

				if ((pos >= sd_listing_pos) && (line < 4))
				{
					strcat(files,"\t/");
					strcat(files,pc_fn);
					strcat(files,"\n");
				}

				pos += 1;
			}
		}
	
		fill_report("sd debug",files, SUCCESS);
	
		// Unmount
		f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
	
	}
}

// */


// TODO - debug format_sd
int format_sd(void)
{
#ifdef TESTING
    fill_report("backup", "Formatting ignored for non-embedded testing.", ERROR);
    return 1;
#else

	if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
		fill_report("backup", "Please insert SD card.", ERROR);
	}

	
    FRESULT res;	
	
	//DWORD plist[] = {100, 0, 0, 0};  // Make one partition 
	//BYTE work[_MAX_SS];
	//res = f_fdisk(LUN_ID_SD_MMC_0_MEM, plist, work);
	//if (FR_OK != res) {
		//fill_report("backup", "Could not partition the SD card.", ERROR);
		//return 3;
	//}
			
	memset(&fs, 0, sizeof(FATFS));
	res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
	if (FR_INVALID_DRIVE == res) {
		fill_report("backup", "Could not mount SD card.", ERROR);
		return 2;
	}
		
	res = f_mkfs(LUN_ID_SD_MMC_0_MEM, 0, 0);
	if (FR_OK != res) {
		fill_report("backup", "Could not format the SD card.", ERROR);
		return 1;
	}

    f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
	
    fill_report("backup", "SD card formated", SUCCESS);
	return 0;
#endif
}


void backup_sd(const char *f, int f_len, const char *t, int t_len)
{
	char file[256] = {0};
	memcpy(file, "0:", 2);
	memcpy(file+2, f, (f_len < 256 - 2) ? f_len : 256 - 2);
	
    char text[256] = {0};
	if (t_len > 256) {
		fill_report("backup", "Text to write is too large.", ERROR);
		return;
	}
    memcpy(text, t, t_len);
#ifdef TESTING
    fill_report("backup", "Ignored for non-embedded testing.", ERROR);
#else
    sd_mmc_init();
	sd_listing_pos = 0;

	if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
		fill_report("backup", "Please insert SD card.", ERROR);
	} else {
		FRESULT res;
		FIL file_object;

		memset(&fs, 0, sizeof(FATFS));
		res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
		if (FR_INVALID_DRIVE == res) {
		    fill_report("backup", "Could not mount SD card.", ERROR);
			return;
		}

		file[0] = LUN_ID_SD_MMC_0_MEM + '0';
		res = f_open(&file_object, (char const *)file, FA_CREATE_ALWAYS | FA_WRITE);
		if (res != FR_OK) {
		    fill_report("backup", "Could not open the file on the SD card.", ERROR);
			return;
		}

		if (0 == f_puts(text, &file_object)) {
			f_close(&file_object);
		    fill_report("backup", "Could not write to the file on the SD card.", ERROR);
			return;
		}
		
        f_close(&file_object);
		fill_report("backup", "success", SUCCESS);
		
		f_mount(LUN_ID_SD_MMC_0_MEM, NULL); 
	}
#endif
}



char *load_sd(const char *f, int f_len)
{
	char file[256] = {0};
	memcpy(file, "0:", 2);
	memcpy(file + 2, f, (f_len < 256 - 2) ? f_len : 256 - 2);

	static char text[256];
	memset(text, 0, sizeof(text));

#ifdef TESTING
	fill_report("load", "Ignored for non-embedded testing.", ERROR);
    return NULL;
#else
    sd_mmc_init();
	sd_listing_pos = 0;

	if (CTRL_FAIL == sd_mmc_test_unit_ready(0)) {
		fill_report("load", "Please insert SD card.", ERROR);
		return NULL;
	}

	FRESULT res;
	FIL file_object;
	memset(&fs, 0, sizeof(FATFS));
	res = f_mount(LUN_ID_SD_MMC_0_MEM, &fs);
	if (FR_INVALID_DRIVE == res) {
		fill_report("load", "Could not mount SD card.", ERROR);
		return NULL;
	}

	file[0] = LUN_ID_SD_MMC_0_MEM + '0';
	res = f_open(&file_object, (char const *)file, FA_OPEN_EXISTING | FA_READ);
	if (res != FR_OK) {
		fill_report("load", "Could not open the file on the SD card.", ERROR);
		return NULL;
	}

	if (0 == f_gets(text, sizeof(text), &file_object)) {
		f_close(&file_object);
		fill_report("load", "Could not read the file on the SD card.", ERROR);
		return NULL;
	}
		
	f_close(&file_object);
	fill_report("load", "success", SUCCESS);
		
	f_mount(LUN_ID_SD_MMC_0_MEM, NULL);
	return text;
#endif
}

