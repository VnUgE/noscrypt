// Copyright (C) 2024 Vaughn Nugent
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

using System;
using System.Reflection;
using static VNLib.Utils.Cryptography.Noscrypt.NoscryptLibrary;

using NCResult = System.Int64;

namespace VNLib.Utils.Cryptography.Noscrypt.@internal
{

    public static class NCUtil
    {


        internal static void CheckResult<T>(NCResult result, bool raiseOnFailure) where T : Delegate
        {
            //Only negative values are errors
            if (result >= NC_SUCCESS)
            {
                return;
            }

            NCResult asPositive = -result;

            // Error code are only 8 bits, if an argument error occured, the
            // argument number will be in the next upper 8 bits
            NCErrorCodes errorCode = (NCErrorCodes)(asPositive & 0xFF);
            byte argNumber = (byte)(asPositive >> 8 & 0xFF);

            switch (errorCode)
            {
                case NCErrorCodes.E_NULL_PTR:
                    RaiseNullArgExceptionForArgumentNumber<T>(argNumber);
                    break;
                case NCErrorCodes.E_INVALID_ARG:
                    RaiseArgExceptionForArgumentNumber<T>(argNumber);
                    break;
                case NCErrorCodes.E_ARGUMENT_OUT_OF_RANGE:
                    RaiseOORExceptionForArgumentNumber<T>(argNumber);
                    break;
                case NCErrorCodes.E_INVALID_CTX:
                    throw new InvalidOperationException("The library context object is null or invalid");
                case NCErrorCodes.E_OPERATION_FAILED:
                    RaiseOperationFailedException(raiseOnFailure);
                    break;
                case NCErrorCodes.E_VERSION_NOT_SUPPORTED:
                    throw new NotSupportedException("The requested version is not supported");

                default:
                    if (raiseOnFailure)
                    {
                        throw new InvalidOperationException($"The operation failed with error, code: {errorCode} for arugment {argNumber:x}");
                    }
                    break;
            }
        }

        private static void RaiseOperationFailedException(bool raise)
        {
            if (raise)
            {
                throw new InvalidOperationException("The operation failed for an unknown reason");
            }
        }

        private static void RaiseNullArgExceptionForArgumentNumber<T>(int argNumber) where T : Delegate
        {
            //Get delegate parameters
            Type type = typeof(T);
            ParameterInfo arg = type.GetMethod("Invoke")!.GetParameters()[argNumber];
            throw new ArgumentNullException(arg.Name, "Argument is null or invalid cannot continue");
        }

        private static void RaiseArgExceptionForArgumentNumber<T>(int argNumber) where T : Delegate
        {
            //Get delegate parameters
            Type type = typeof(T);
            ParameterInfo arg = type.GetMethod("Invoke")!.GetParameters()[argNumber];
            throw new ArgumentException("Argument is null or invalid cannot continue", arg.Name);
        }

        private static void RaiseOORExceptionForArgumentNumber<T>(int argNumber) where T : Delegate
        {
            //Get delegate parameters
            Type type = typeof(T);
            ParameterInfo arg = type.GetMethod("Invoke")!.GetParameters()[argNumber];
            throw new ArgumentOutOfRangeException(arg.Name, "Argument is out of range of acceptable values");
        }
    }
}
