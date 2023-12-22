﻿/*
   Copyright CrypTool 2 Team josef.matwich@gmail.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
using System;
using System.IO;

namespace M209AnalyzerLib.Common
{
    public static class Logger
    {
        public static string LogPath;
        public static void WriteLog(string message)
        {
            if (LogPath != String.Empty)
            {
                using (StreamWriter writer = new StreamWriter(LogPath, true))
                {
                    writer.WriteLine($"{DateTime.Now} - {message}");
                }

            }
        }
    }
}
