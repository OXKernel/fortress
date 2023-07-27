/*
 * Copyright (C) 2023. Roger Doss. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <termios.h>

void turn_off_echo()
{
    termios oldt;
    tcgetattr(fileno(stdin), &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(fileno(stdin), TCSANOW, &newt);
}// turn_off_echo

void turn_on_echo()
{
    termios oldt;
    tcgetattr(fileno(stdin), &oldt);
    termios newt = oldt;
    newt.c_lflag |= (ICANON | ECHO);
    tcsetattr(fileno(stdin), TCSANOW, &newt);
}// turn_on_echo

char *get_password(const char *prompt)
{
    static const int PASS_MAX = 1024;
    int ch = 0;
    char *password = new char[PASS_MAX], *ptr = password;
    memset(password,0x0,PASS_MAX);
	  // Linux
    turn_off_echo();
    printf("%s\n",prompt);
 
    while((ch=getc(stdin)) != '\n') {
        if((ptr-password) >= PASS_MAX) {
            fprintf(stderr," error password exceeds limit of [%d] characters\n",PASS_MAX);
            exit(1);
        }
        *ptr++ = ch;
        turn_on_echo();
        printf("*");
        fflush(stdout);
        turn_off_echo();
    }
    turn_on_echo();
    return password;
} // get_password
