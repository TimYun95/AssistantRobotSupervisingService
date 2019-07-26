using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Drawing;
using System.Configuration;

using LogPrinter;
using Emgu.CV;
using Emgu.CV.Structure;
using Emgu.CV.CvEnum;

namespace AssistantRobotSupervisingService
{
    public class ServerFunction
    {
        /// <summary>
        /// 协议关键字
        /// </summary>
        public enum VideoTransferProtocolKey : byte
        {
            Header1 = 34,
            Header2 = 84,
            RSAKey = 104,
            AESKey = 108,
            BeginTransferVideo = 114,
            VideoTransfer = 204,
            PingSignal = 244,
            EndTransferVideo = 254
        }

        /// <summary>
        /// 密钥数据报格式
        /// </summary>
        public enum SecurityKeyLength : int
        {
            AESIVLength = 16,
            AESKeyLength = 32,
            RSAKeyLength = 1024
        }

        #region 字段
        private readonly bool ifAtSamePC = true;

        private const int clientPortTCPAtSamePC = 40007;
        private const int clientPortUDPAtSamePC = 40008;
        private const string serverIPAtSamePC = "127.0.0.1";

        private const int clientPortTCPAtDiffPC = 40005;
        private const int clientPortUDPAtDiffPC = 40006;
        private readonly string serverIPAtDiffPC = "192.168.1.13"; // 应该是192.168.1.13

        private const int serverPortTCPAny = 40005;
        private const int serverPortUDPAny = 40006;

        private Socket tcpListenSocket;
        private CancellationTokenSource tcpListenCancel;
        private Task tcpListenTask;

        private Socket tcpTransferSocket;
        private bool tcpTransferSocketEstablished = false;
        private bool ifGetVideoSendCmdOnce = false;
        private readonly int tcpTransferSocketRecieveTimeOut = 3 * 1000;
        private System.Timers.Timer tcpBeatClocker;
        private CancellationTokenSource tcpTransferCancel;
        private Task tcpTransferRecieveTask;
        private IPEndPoint remoteIPEndPoint;
        private byte? remoteDeviceIndex = null;
        private string remoteDevicePublicKey = null;
        private const int remoteDevicePublicKeyLength = 1024;

        private Socket udpTransferSocket;
        private readonly int udpTransferSocketInterval = 150;
        private readonly int udpTransferSocketSendTimeOut = 500;
        private System.Timers.Timer udpSendClocker;
        private bool limitEnterClock = false;
        private CancellationTokenSource udpTransferCancel;
        private Task udpTransferSendTask;
        private const int udpMaxQueue = 100;
        private Queue<byte[]> udpTransferSendQueue = new Queue<byte[]>(udpMaxQueue);
        private const int waitTimeMs = 5;
        private static readonly object queueLocker = new object();

        private byte[] commonKey = null;
        private byte[] commonIV = null;

        private readonly int cameraIndex = 0;
        private readonly int cameraFps = 10;
        private readonly int cameraHeight = 640;
        private readonly int cameraWidth = 480;
        private Capture camera;
        private const int maxVideoByteLength = 60000;
        private byte packIndex = 0;

        public delegate void SendCloseService();
        public event SendCloseService OnSendCloseService;
        private static readonly object closeSideLocker = new object();
        private bool lockCloseSide = false;
        private bool ifCloseFromInnerSide = true;
        #endregion

        #region 方法
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="ifSuccessConstructed">是否成功构造</param>
        public ServerFunction(out bool ifSuccessConstructed)
        {
            // 检查环境
            if (!Functions.CheckEnvironment())
            {
                ifSuccessConstructed = false;
                return;
            }
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service starts with successful checked.");

            // 加载程序配置
            bool parseResult = true;

            bool ifAtSamePCTemp;
            parseResult = bool.TryParse(ConfigurationManager.AppSettings["ifAtSamePC"], out ifAtSamePCTemp);
            if (parseResult) ifAtSamePC = ifAtSamePCTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "ifAtSamePC" + ") is wrong.");
                return;
            }

            string serverIPAtDiffPCTemp = ConfigurationManager.AppSettings["serverIPAtDiffPC"];
            if (new string(serverIPAtDiffPCTemp.Take(10).ToArray()) == "192.168.1.") serverIPAtDiffPC = serverIPAtDiffPCTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "serverIPAtDiffPC" + ") is wrong.");
                return;
            }

            int tcpTransferSocketRecieveTimeOutTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["tcpTransferSocketRecieveTimeOut"], out tcpTransferSocketRecieveTimeOutTemp);
            if (parseResult) tcpTransferSocketRecieveTimeOut = tcpTransferSocketRecieveTimeOutTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "tcpTransferSocketRecieveTimeOut" + ") is wrong.");
                return;
            }

            int udpTransferSocketIntervalTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["udpTransferSocketInterval"], out udpTransferSocketIntervalTemp);
            if (parseResult) udpTransferSocketInterval = udpTransferSocketIntervalTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "udpTransferSocketInterval" + ") is wrong.");
                return;
            }

            int udpTransferSocketSendTimeOutTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["udpTransferSocketSendTimeOut"], out udpTransferSocketSendTimeOutTemp);
            if (parseResult) udpTransferSocketSendTimeOut = udpTransferSocketSendTimeOutTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "udpTransferSocketSendTimeOut" + ") is wrong.");
                return;
            }

            int cameraIndexTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["cameraIndex"], out cameraIndexTemp);
            if (parseResult) cameraIndex = cameraIndexTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "cameraIndex" + ") is wrong.");
                return;
            }

            int cameraFpsTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["cameraFps"], out cameraFpsTemp);
            if (parseResult) cameraFps = cameraFpsTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "cameraFps" + ") is wrong.");
                return;
            }

            int cameraHeightTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["cameraHeight"], out cameraHeightTemp);
            if (parseResult) cameraHeight = cameraHeightTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "cameraHeight" + ") is wrong.");
                return;
            }

            int cameraWidthTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["cameraWidth"], out cameraWidthTemp);
            if (parseResult) cameraWidth = cameraWidthTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "cameraWidth" + ") is wrong.");
                return;
            }

            // 装上UDP定时器
            udpSendClocker = new System.Timers.Timer(udpTransferSocketInterval);
            udpSendClocker.AutoReset = true;
            udpSendClocker.Elapsed += udpSendClocker_Elapsed;

            // 装上TCP心跳定时器
            tcpBeatClocker = new System.Timers.Timer(tcpTransferSocketRecieveTimeOut / 2);
            tcpBeatClocker.AutoReset = false;
            tcpBeatClocker.Elapsed += tcpBeatClocker_Elapsed;

            ifSuccessConstructed = true;
        }

        /// <summary>
        /// 开始监听循环
        /// </summary>
        public void StartListenLoop()
        {
            // TCP侦听循环开始
            tcpListenCancel = new CancellationTokenSource();
            tcpListenTask = new Task(() => TcpListenTaskWork(tcpListenCancel.Token));
            tcpListenTask.Start();
        }

        /// <summary>
        /// 关闭监听循环
        /// </summary>
        /// <returns>返回监听循环任务</returns>
        public Task StopListenLoop()
        {
            lock (closeSideLocker)
            {
                lockCloseSide = true;
                ifCloseFromInnerSide = false;
            }
            tcpListenCancel.Cancel();
            EndAllLoop();

            return tcpListenTask;
        }

        /// <summary>
        /// TCP监听任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void TcpListenTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp listener begins.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                // 刷新公共密钥
                using (AesCryptoServiceProvider tempAes = new AesCryptoServiceProvider())
                {
                    tempAes.GenerateKey();
                    tempAes.GenerateIV();
                    commonKey = tempAes.Key;
                    commonIV = tempAes.IV;
                }

                // UDP传输socket建立
                udpTransferSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                udpTransferSocket.Bind(new IPEndPoint(IPAddress.Parse(ifAtSamePC ? serverIPAtSamePC : serverIPAtDiffPC), serverPortUDPAny));
                udpTransferSocket.SendTimeout = udpTransferSocketSendTimeOut;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer initials.");

                // TCP侦听socket建立 开始侦听
                tcpListenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcpListenSocket.Bind(new IPEndPoint(IPAddress.Parse(ifAtSamePC ? serverIPAtSamePC : serverIPAtDiffPC), serverPortTCPAny));
                tcpListenSocket.Listen(1);
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp listener begins to listen.");

                // TCP侦听socket等待连接建立
                IAsyncResult acceptResult = tcpListenSocket.BeginAccept(null, null);
                do
                {
                    if (cancelFlag.IsCancellationRequested) break;
                    acceptResult.AsyncWaitHandle.WaitOne(1000, true);  //等待1秒
                } while (!acceptResult.IsCompleted);
                if (cancelFlag.IsCancellationRequested) // 不再accept等待
                {
                    // 清理连接
                    FinishAllConnection();
                    if (ifGetVideoSendCmdOnce) camera.Dispose();

                    // 清空公钥和设备号
                    remoteDeviceIndex = null;
                    remoteDevicePublicKey = null;
                    ifGetVideoSendCmdOnce = false;
                    break;
                }
                tcpTransferSocket = tcpListenSocket.EndAccept(acceptResult);
                tcpTransferSocketEstablished = true;
                tcpTransferSocket.ReceiveTimeout = tcpTransferSocketRecieveTimeOut;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer connection is established.");

                // TCP连接建立之后关闭侦听socket
                tcpListenSocket.Close();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp listener is closed.");

                // TCP连接建立之后保存远端传输socket
                remoteIPEndPoint = (IPEndPoint)tcpTransferSocket.RemoteEndPoint;
                remoteIPEndPoint.Port = ifAtSamePC ? clientPortUDPAtSamePC : clientPortUDPAtDiffPC;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Remote IP is saved.");

                // TCP侦听socket关闭后 开始允许TCP传输socket接收数据
                tcpTransferCancel = new CancellationTokenSource();
                tcpTransferRecieveTask = new Task(() => TcpTransferRecieveTaskWork(tcpTransferCancel.Token));
                tcpTransferRecieveTask.Start();

                // 打开心跳定时器
                tcpBeatClocker.Start();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Beats is required.");

                // 等待直到TCP传输结束接收数据
                tcpTransferRecieveTask.Wait();

                // 等待直到UDP传输结束发送数据
                udpTransferSendTask.Wait();

                // 准备再次进行监听
                FinishAllConnection();
                if (ifGetVideoSendCmdOnce) camera.Dispose();
                Thread.Sleep(1000);

                // 清空公钥和设备号
                commonKey = null;
                commonIV = null; 
                remoteDeviceIndex = null;
                remoteDevicePublicKey = null;
                ifGetVideoSendCmdOnce = false;

                // 清空缓存
                udpTransferSendQueue.Clear();
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp listener stops.");

            if (ifCloseFromInnerSide)
            {
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service close from inner side.");
                OnSendCloseService();
            }
        }

        /// <summary>
        /// 心跳定时器
        /// </summary>
        private void tcpBeatClocker_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            EndAllLoop();
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer recieve no beats in definite time.");
        }

        /// <summary>
        /// TCP接收数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void TcpTransferRecieveTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer begins to recieve datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                try
                {
                    byte[] reciveDatas = new byte[1024 + 8];
                    int actualLength = tcpTransferSocket.Receive(reciveDatas);
                    DealWithTcpTransferRecieveDatas(reciveDatas.Take(actualLength).ToArray());
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        EndAllLoop();
                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer recieve no datas in definite time.");
                    }
                    else
                    {
                        lock (closeSideLocker)
                        {
                            if (!lockCloseSide) ifCloseFromInnerSide = true;
                        }
                        tcpListenCancel.Cancel(); // 退出监听
                        EndAllLoop();
                        Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                    }
                }
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer stops to recieve datas.");
        }

        /// <summary>
        /// 处理TCP接收的数据
        /// </summary>
        /// <param name="datas">所收数据</param>
        private void DealWithTcpTransferRecieveDatas(byte[] datas)
        {
            if (datas.Length < 4) return; // 长度不可能出现
            if (datas[0] != (byte)VideoTransferProtocolKey.Header1 ||
                datas[1] != (byte)VideoTransferProtocolKey.Header2) return; // 协议头不匹配

            byte deviceIndex = datas[2];
            VideoTransferProtocolKey workCmd = (VideoTransferProtocolKey)datas[3];

            switch (workCmd)
            {
                case VideoTransferProtocolKey.RSAKey:
                    int keyLength = Convert.ToInt32(
                                              IPAddress.NetworkToHostOrder(
                                              BitConverter.ToInt32(datas, 4)));
                    if (keyLength != datas.Length - 8) return; // 长度不匹配

                    remoteDeviceIndex = deviceIndex;
                    remoteDevicePublicKey = Encoding.UTF8.GetString(datas, 8, keyLength);

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSAKey saved.");

                    // 发送AES密钥
                    SendAESKey();

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AESKey sent.");
                    break;
                case VideoTransferProtocolKey.BeginTransferVideo:
                    if (!ifGetVideoSendCmdOnce && remoteDeviceIndex == deviceIndex)
                    {
                        // 若未收到过发送视频指令 打开UDP传输定时器
                        ifGetVideoSendCmdOnce = true;

                        camera = new Capture(cameraIndex);
                        camera.SetCaptureProperty(CapProp.Fps, cameraFps);
                        camera.SetCaptureProperty(CapProp.FrameHeight, cameraHeight);
                        camera.SetCaptureProperty(CapProp.FrameWidth, cameraWidth);

                        // 重置标志
                        udpTransferSendQueue.Clear();
                        packIndex = 0;

                        udpSendClocker.Start();

                        udpTransferCancel = new CancellationTokenSource();
                        udpTransferSendTask = new Task(() => UdpTransferSendTaskWork(udpTransferCancel.Token));
                        udpTransferSendTask.Start();

                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Begin send video.");
                    }
                    break;
                case VideoTransferProtocolKey.PingSignal:
                    if (remoteDeviceIndex != deviceIndex) return; // 设备号不匹配
                    tcpBeatClocker.Stop();
                    tcpBeatClocker.Start();
                    break;
                case VideoTransferProtocolKey.EndTransferVideo:
                    if (ifGetVideoSendCmdOnce && remoteDeviceIndex == deviceIndex)
                    {
                        // 若收到过发送视频指令 准备关闭连接
                        EndAllLoop();

                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "End send video.");
                    }
                    break;
                default:
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "No such control command.");
                    break;
            }
        }

        /// <summary>
        /// 发送AES密钥
        /// </summary>
        private void SendAESKey()
        {
            List<byte> aesKey = new List<byte>((int)SecurityKeyLength.AESIVLength + (int)SecurityKeyLength.AESKeyLength);
            aesKey.AddRange(commonIV);
            aesKey.AddRange(commonKey);
            byte[] keyDatas = EncryptByRSA(aesKey.ToArray()); // 加密数据内容

            List<byte> sendBytes = new List<byte>(4);
            sendBytes.Add((byte)VideoTransferProtocolKey.Header1);
            sendBytes.Add((byte)VideoTransferProtocolKey.Header2);
            sendBytes.Add(remoteDeviceIndex.Value);
            sendBytes.Add((byte)VideoTransferProtocolKey.AESKey);
            sendBytes.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(keyDatas.Length)));
            sendBytes.AddRange(keyDatas);

            try
            {
                tcpTransferSocket.Send(sendBytes.ToArray());
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionAborted || ex.SocketErrorCode == SocketError.TimedOut)
                {
                    EndAllLoop();
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service tcp transfer send AES key failed.");
                }
                else
                {
                    lock (closeSideLocker)
                    {
                        if (!lockCloseSide) ifCloseFromInnerSide = true;
                    }
                    tcpListenCancel.Cancel(); // 退出监听
                    EndAllLoop();
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                }
            }
        }

        #region 加解密
        /// <summary>
        /// RSA公钥加密数据
        /// </summary>
        /// <param name="nonEncryptedBytes">待加密字节流</param>
        /// <returns>加密后的字节流</returns>
        private byte[] EncryptByRSA(byte[] nonEncryptedBytes)
        {
            if (Object.Equals(nonEncryptedBytes, null) || nonEncryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for encrypting by RSA is abnormal.");
                return null; // 待加密数据异常
            }
            if (Object.Equals(remoteDevicePublicKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSA public key has not been known yet.");
                return null; // RSA公钥未知
            }

            byte[] encryptedBytes = null;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(remoteDevicePublicKey);
                if (nonEncryptedBytes.Length > ((int)SecurityKeyLength.RSAKeyLength) / 8 - 11) return null; // 待加密数据过长

                encryptedBytes = rsa.Encrypt(nonEncryptedBytes, false);
            }
            return encryptedBytes;
        }

        /// <summary>
        /// AES加密数据
        /// </summary>
        /// <param name="nonEncryptedBytes">待加密字节流</param>
        /// <returns>加密后的字节流</returns>
        private byte[] EncryptByAES(byte[] nonEncryptedBytes)
        {
            if (Object.Equals(nonEncryptedBytes, null) || nonEncryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for encrypting by AES is abnormal.");
                return null; // 待加密数据异常
            }
            if (Object.Equals(commonIV, null) ||
                Object.Equals(commonKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AES key has not been known yet.");
                return null; // AES密钥和初始向量未知
            }

            string nonEncryptedString = Convert.ToBase64String(nonEncryptedBytes);

            byte[] encryptedBytes = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = commonKey; aes.IV = commonIV;
                ICryptoTransform encryptorByAES = aes.CreateEncryptor();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptorByAES, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(nonEncryptedString);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }

            return encryptedBytes;
        }

        /// <summary>
        /// AES解密数据
        /// </summary>
        /// <param name="encryptedBytes">待解密字节流</param>
        /// <returns>解密后的字节流</returns>
        private byte[] DecryptByAES(byte[] encryptedBytes)
        {
            if (Object.Equals(encryptedBytes, null) || encryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for decrypting by AES is abnormal.");
                return null; // 待解密数据异常
            }
            if (Object.Equals(commonIV, null) ||
                Object.Equals(commonKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AES key has not been known yet.");
                return null; // AES密钥和初始向量未知
            }

            byte[] decryptedBytes = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = commonKey; aes.IV = commonIV;
                ICryptoTransform decryptorByAES = aes.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptorByAES, CryptoStreamMode.Read))
                    {
                        using (StreamReader swDecrypt = new StreamReader(csDecrypt))
                        {
                            string decryptedString = swDecrypt.ReadToEnd();
                            decryptedBytes = Convert.FromBase64String(decryptedString);
                        }
                    }
                }
            }
            return decryptedBytes;
        }
        #endregion

        /// <summary>
        /// 结束所有循环等待
        /// </summary>
        private void EndAllLoop()
        {
            if (!Object.Equals(tcpTransferCancel, null))
            {
                tcpTransferCancel.Cancel();
            }
            udpSendClocker.Stop();
            if (!Object.Equals(udpTransferCancel, null))
            {
                udpTransferCancel.Cancel();
            }
            tcpBeatClocker.Stop();
        }

        /// <summary>
        /// 结束所有连接
        /// </summary>
        private void FinishAllConnection()
        {
            if (tcpTransferSocketEstablished)
            {
                tcpTransferSocket.Shutdown(SocketShutdown.Both);
                tcpTransferSocket.Close();
                tcpTransferSocketEstablished = false;
            }

            Thread.Sleep(udpTransferSocketInterval);
            udpTransferSocket.Shutdown(SocketShutdown.Both);
            udpTransferSocket.Close();
        }

        /// <summary>
        /// UDP传输视频定时器
        /// </summary>
        private void udpSendClocker_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (limitEnterClock) return;
            limitEnterClock = true;

            // 得到图像
            Mat pic = new Mat();
            camera.Retrieve(pic, 0);

            // 得到图像压缩后的字节流
            byte[] imgBytes;
            Bitmap ImgBitmap = pic.ToImage<Bgr, byte>().Bitmap;
            using (MemoryStream ms = new MemoryStream())
            {
                ImgBitmap.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                imgBytes = ms.GetBuffer();
            }

            // 利用公钥加密
            byte[] encryptedBytes = EncryptByAES(imgBytes);
            limitEnterClock = false;
            if (Object.Equals(encryptedBytes, null)) return;

            // 入队待发送
            if (!ifGetVideoSendCmdOnce) return;
            lock (queueLocker)
            {
                if (udpTransferSendQueue.Count >= udpMaxQueue)
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Udp buffer is full, consider to slow pic capture.");
                else
                    udpTransferSendQueue.Enqueue(encryptedBytes);
            }
        }

        /// <summary>
        /// UDP发送数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void UdpTransferSendTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer begins to send datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                byte[] readyToSendBytes = null;
                lock (queueLocker)
                {
                    if (udpTransferSendQueue.Count > 0)
                        readyToSendBytes = udpTransferSendQueue.Dequeue();
                }
                if (Object.Equals(readyToSendBytes, null))
                {
                    Thread.Sleep(waitTimeMs);
                    continue;
                }

                SendVideoPart(readyToSendBytes, cancelFlag);
            }
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer stops to send datas.");
        }

        // 格式 = Header1 + Header2 + DeviceIndex + FunctionCode + DataLength + PackIndex + PackCount + PackNum + PackData
        //             协议头1      协议头2          设备号              功能码             数据长度          包索引           分包数           当前包        包内容
        // 字节 =       1                1                   1                      1                      4                    1                   1                   1           <= maxVideoByteLength    
        //                                                                                                   数据长度 = 包索引 +  分包数 + 当前包 + 包内容 <= maxVideoByteLength + 3
        /// <summary>
        /// 发送视频块
        /// </summary>
        /// <param name="sendBytes">发送的字节</param>
        /// <param name="cancelFlag">停止标志</param>
        private void SendVideoPart(byte[] sendBytesList, CancellationToken cancelFlag)
        {
            int packDataLength = sendBytesList.Length;
            int packCount = packDataLength / maxVideoByteLength + 1;
            packIndex = (byte)(packIndex % byte.MaxValue + 1);

            for (int i = 0; i < packCount - 1; ++i)
            {
                List<byte> sendPack = new List<byte>(maxVideoByteLength + 11);
                sendPack.Add((byte)VideoTransferProtocolKey.Header1);
                sendPack.Add((byte)VideoTransferProtocolKey.Header2);
                sendPack.Add(remoteDeviceIndex.HasValue ? remoteDeviceIndex.Value : byte.MinValue);
                sendPack.Add((byte)VideoTransferProtocolKey.VideoTransfer);
                sendPack.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packDataLength + 3)));
                sendPack.Add(packIndex);
                sendPack.Add((byte)packCount);
                sendPack.Add((byte)(i + 1));
                sendPack.AddRange(sendBytesList.Skip(i * maxVideoByteLength).Take(maxVideoByteLength));

                if (cancelFlag.IsCancellationRequested) return;
                try
                {
                    udpTransferSocket.SendTo(sendPack.ToArray(), remoteIPEndPoint);
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        EndAllLoop();
                        Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer can not send datas in definite time.");
                        return;
                    }
                    else
                    {
                        lock (closeSideLocker)
                        {
                            if (!lockCloseSide) ifCloseFromInnerSide = true;
                        }
                        tcpListenCancel.Cancel(); // 退出监听
                        EndAllLoop();
                        Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                        return;
                    }
                }
                Thread.Sleep(waitTimeMs);
            }

            List<byte> sendFinalPack = new List<byte>(packDataLength - (packCount - 1) * maxVideoByteLength + 11);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.Header1);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.Header2);
            sendFinalPack.Add(remoteDeviceIndex.HasValue ? remoteDeviceIndex.Value : byte.MinValue);
            sendFinalPack.Add((byte)VideoTransferProtocolKey.VideoTransfer);
            sendFinalPack.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(packDataLength + 3)));
            sendFinalPack.Add(packIndex);
            sendFinalPack.Add((byte)packCount);
            sendFinalPack.Add((byte)packCount);
            sendFinalPack.AddRange(sendBytesList.Skip((packCount - 1) * maxVideoByteLength));

            if (cancelFlag.IsCancellationRequested) return;
            try
            {
                udpTransferSocket.SendTo(sendFinalPack.ToArray(), remoteIPEndPoint);
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.TimedOut)
                {
                    EndAllLoop();
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service udp transfer can not send datas in definite time.");
                    return;
                }
                else
                {
                    lock (closeSideLocker)
                    {
                        if (!lockCloseSide) ifCloseFromInnerSide = true;
                    }
                    tcpListenCancel.Cancel(); // 退出监听
                    EndAllLoop();
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                    return;
                }
            }
            Thread.Sleep(waitTimeMs);

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Send package [" + packIndex.ToString() + "] of " + packDataLength.ToString() + " bytes with " + packCount + " segments.");
        }
        #endregion
    }
}
