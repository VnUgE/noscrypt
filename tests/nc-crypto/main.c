/*
* Copyright (c) 2026 Vaughn Nugent
*
* Package: noscrypt
* File: nc-crypto/main.c
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation; either version 2.1
* of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with noscrypt. If not, see http://www.gnu.org/licenses/.
*/

#include <test.h>

extern int StreamTests(void);
extern int VectorTests(void);

/* entrypoint for tests */
int RunTests(void)
{
	TEST_GROUP(StreamTests());
	TEST_GROUP(VectorTests());

	return 0;
}
