using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Net;
using System.Net.Sockets;
using System.Management;
using Newtonsoft.Json;
using System.IO;
using System.Diagnostics;
using Microsoft.VisualBasic.Devices;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SocketsServer
{
    /// <summary>
    /// Lógica de interacción para MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {


        //private readonly Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        //private readonly List<Socket> clientSockets = new List<Socket>();
        //private const int BUFFER_SIZE = 2048;
        private const int PORT = 100;
        private string IP = "";
        //private readonly byte[] buffer = new byte[BUFFER_SIZE];

        private static int _listeningPort = 2000;
        public MainWindow()
        {
            InitializeComponent();
            
        }


        private void SetupServer()
        {
            //Console.WriteLine("Levantando Servidor...");
            //lblServerStatus.Content = "Levantando Servidor...";

            //serverSocket.Bind(new IPEndPoint(IPAddress.Parse(IP), PORT));
            //serverSocket.Listen(0);
            ////serverSocket.BeginAccept(AcceptCallback, null);

            //Console.WriteLine("Servidor Activo");
            //lblServerStatus.Content = "Servidor Activo";



        }


        #region Sockets Methods


        /// <summary>
        /// Método recursivo para aceptar diferentes conexiones simultaneas
        /// </summary>
        /// <param name="AR"></param>
        //private void AcceptCallback(IAsyncResult AR)
        //{
        //    //Socket socket;

        //    //try
        //    //{
        //    //    socket = serverSocket.EndAccept(AR);
        //    //}
        //    //catch (ObjectDisposedException)
        //    //{
        //    //    return;
        //    //}

        //    //clientSockets.Add(socket);
        //    //socket.BeginReceive(buffer, 0, BUFFER_SIZE, SocketFlags.None, ReceiveCallback, socket);

        //    //Console.WriteLine("Cliente conectado, esperando petición...");

        //    //serverSocket.BeginAccept(AcceptCallback, null);
        //}


        /// <summary>
        /// Método para recibir la petición de un cliente
        /// </summary>
        /// <param name="AR"></param>
        private void ReceiveCallback(IAsyncResult AR)
        {
            //Socket current = (Socket)AR.AsyncState;
            //int received;

            //try
            //{
            //    received = current.EndReceive(AR);
            //}
            //catch (SocketException)
            //{
            //    Console.WriteLine("Cliente desconectado forzadamente");
            //    current.Close();
            //    clientSockets.Remove(current);
            //    return;
            //}

            //byte[] recBuf = new byte[received];
            //Array.Copy(buffer, recBuf, received);
            //string text = Encoding.ASCII.GetString(recBuf);

            //Console.WriteLine("Texto Recibido: " + text);
            //this.Dispatcher.Invoke(() => {
            //    lblReceived.Content = text;
            //});

            //if (text == "getVideoController") // Información de tarjetas gráficas
            //{
            //    Console.WriteLine("Text is a get video controller request");
            //    List<GPU> videoControllers = new List<GPU>();
            //    ManagementObjectSearcher myVideoObject = new ManagementObjectSearcher("select * from Win32_VideoController");
            //    foreach (ManagementObject obj in myVideoObject.Get())
            //    {
            //        videoControllers.Add(new GPU()
            //        {
            //            Name = obj["Name"].ToString(),
            //            Status = obj["Status"].ToString(),
            //            AdapterRAM = obj["AdapterRAM"].ToString(),
            //            AdapterDACType = obj["AdapterDACType"].ToString(),
            //            DriverVersion = obj["DriverVersion"].ToString()
            //        });
            //    }
            //    string result = JsonConvert.SerializeObject(videoControllers);
            //    byte[] data = Encoding.ASCII.GetBytes(result);
            //    current.Send(data);
            //    Console.WriteLine("Info sent to client");
            //} else if (text == "getStorage") // Información de los discos de almacenamiento
            //{
            //    Console.WriteLine("Text is a get storage request");
            //    List<Storage> storages = new List<Storage>();
            //    DriveInfo[] allDrives = DriveInfo.GetDrives();
            //    foreach (DriveInfo d in allDrives)
            //    {
            //        if (d.IsReady == true)
            //        {
            //            storages.Add(new Storage()
            //            {
            //                TotalAvailableSpace = d.TotalFreeSpace,
            //                TotalSizeOfDrive = d.TotalSize,
            //                RootDirectory = d.RootDirectory.Name
            //            });
            //        }
            //    }
            //    string result = JsonConvert.SerializeObject(storages);
            //    byte[] data = Encoding.ASCII.GetBytes(result);
            //    current.Send(data);
            //    Console.WriteLine("Info sent to client");
            //}
            //else if (text == "getMemoryRam") // Información de la memoria ram
            //{
            //    Console.WriteLine("Text is a get memory ram request");
            //    PerformanceCounter ram = new PerformanceCounter();
            //    ComputerInfo infoDevice = new ComputerInfo();
            //    ram.CategoryName = "Memory";
            //    ram.CounterName = "Available Bytes";
            //    MemoryRam memoryRam = new MemoryRam()
            //    {
            //        TotalPhysicalMemory = infoDevice.TotalPhysicalMemory,
            //        TotalFreeSpace = ram.NextValue()
            //    };
            //    string result = JsonConvert.SerializeObject(memoryRam);
            //    byte[] data = Encoding.ASCII.GetBytes(result);
            //    current.Send(data);
            //    Console.WriteLine("Info sent to client");
            //}
            //else if (text == "getAll") // Toda la información
            //{
            //    Console.WriteLine("Text is a get all request");
            //    All all = new All()
            //    {
            //        GPUs = new List<GPU>(),
            //        Storages = new List<Storage>()
            //    };
            //    ManagementObjectSearcher myVideoObject = new ManagementObjectSearcher("select * from Win32_VideoController");
            //    foreach (ManagementObject obj in myVideoObject.Get())
            //    {
            //        all.GPUs.Add(new GPU()
            //        {
            //            Name = obj["Name"].ToString(),
            //            Status = obj["Status"].ToString(),
            //            AdapterRAM = obj["AdapterRAM"].ToString(),
            //            AdapterDACType = obj["AdapterDACType"].ToString(),
            //            DriverVersion = obj["DriverVersion"].ToString()
            //        });
            //    }
            //    DriveInfo[] allDrives = DriveInfo.GetDrives();
            //    foreach (DriveInfo d in allDrives)
            //    {
            //        if (d.IsReady == true)
            //        {
            //            all.Storages.Add(new Storage()
            //            {
            //                TotalAvailableSpace = d.TotalFreeSpace,
            //                TotalSizeOfDrive = d.TotalSize,
            //                RootDirectory = d.RootDirectory.Name
            //            });
            //        }
            //    }
            //    PerformanceCounter ram = new PerformanceCounter();
            //    ComputerInfo infoDevice = new ComputerInfo();
            //    ram.CategoryName = "Memory";
            //    ram.CounterName = "Available Bytes";
            //    all.MemoryRam = new MemoryRam()
            //    {
            //        TotalPhysicalMemory = infoDevice.TotalPhysicalMemory,
            //        TotalFreeSpace = ram.NextValue()
            //    };
            //    string result = JsonConvert.SerializeObject(all);
            //    byte[] data = Encoding.ASCII.GetBytes(result);
            //    current.Send(data);
            //    Console.WriteLine("Info sent to client");
            //}
            //else if (text == "exit")
            //{
            //    current.Shutdown(SocketShutdown.Both);
            //    current.Close();
            //    clientSockets.Remove(current);
            //    Console.WriteLine("Cliente desconectado");
            //    return;
            //}
            //else
            //{
            //    Console.WriteLine("Peticion Invalida");
            //    byte[] data = Encoding.ASCII.GetBytes("Peticion Invalida");
            //    current.Send(data);
            //    Console.WriteLine("Alerta Enviada");
            //}

            //current.BeginReceive(buffer, 0, BUFFER_SIZE, SocketFlags.None, ReceiveCallback, current);
        }
        #endregion


        private void btnSetUpServer_Click(object sender, RoutedEventArgs e)
        {
            
            try
            {
                IP = txtIp.Text;
               
                var serverCertificate = getServerCert();

                var listener = new TcpListener(IPAddress.Parse(IP), _listeningPort);
                listener.Start();
                
                while (true)
                {
                    using (var client = listener.AcceptTcpClient())
                    using (var sslStream = new SslStream(client.GetStream(), false, ValidateCertificate))
                    {
                        sslStream.AuthenticateAsServer(serverCertificate, true, SslProtocols.Tls12, false);

                        Console.WriteLine("Esperando Mensaje...\n==================================");
                        lblServerStatus.Content = "Servidor Activo";
                        byte[] inputBuffer = new byte[4096];
                        int inputBytes = 0;
                        while (inputBytes == 0)
                        {
                            inputBytes = sslStream.Read(inputBuffer, 0, inputBuffer.Length);
                        }

                        string text = Encoding.UTF8.GetString(inputBuffer, 0, inputBytes);

                        Console.WriteLine("Texto Recibidooioo: " + text);
                        lblReceived.Content = text;
                       
                        string result = "";
                        if (text == "getVideoController") // Información de tarjetas gráficas
                        {
                            Console.WriteLine("Text is a get video controller request");
                            List<GPU> videoControllers = new List<GPU>();
                            ManagementObjectSearcher myVideoObject = new ManagementObjectSearcher("select * from Win32_VideoController");
                            foreach (ManagementObject obj in myVideoObject.Get())
                            {
                                videoControllers.Add(new GPU()
                                {
                                    Name = obj["Name"].ToString(),
                                    Status = obj["Status"].ToString(),
                                    AdapterRAM = obj["AdapterRAM"].ToString(),
                                    AdapterDACType = obj["AdapterDACType"].ToString(),
                                    DriverVersion = obj["DriverVersion"].ToString()
                                });
                            }
                            result = JsonConvert.SerializeObject(videoControllers);
                           
                            Console.WriteLine("Info sent to client");
                        }
                        else if (text == "getStorage") // Información de los discos de almacenamiento
                        {
                            Console.WriteLine("Text is a get storage request");
                            List<Storage> storages = new List<Storage>();
                            DriveInfo[] allDrives = DriveInfo.GetDrives();
                            foreach (DriveInfo d in allDrives)
                            {
                                if (d.IsReady == true)
                                {
                                    storages.Add(new Storage()
                                    {
                                        TotalAvailableSpace = d.TotalFreeSpace,
                                        TotalSizeOfDrive = d.TotalSize,
                                        RootDirectory = d.RootDirectory.Name
                                    });
                                }
                            }
                            result = JsonConvert.SerializeObject(storages);
                            
                            Console.WriteLine("Info sent to client");
                        }
                        else if (text == "getMemoryRam") // Información de la memoria ram
                        {
                            Console.WriteLine("Text is a get memory ram request");
                            PerformanceCounter ram = new PerformanceCounter();
                            ComputerInfo infoDevice = new ComputerInfo();
                            ram.CategoryName = "Memory";
                            ram.CounterName = "Available Bytes";
                            MemoryRam memoryRam = new MemoryRam()
                            {
                                TotalPhysicalMemory = infoDevice.TotalPhysicalMemory,
                                TotalFreeSpace = ram.NextValue()
                            };
                            result = JsonConvert.SerializeObject(memoryRam);
                            
                            Console.WriteLine("dfd", result);

                            Console.WriteLine("Info sent to client rammmmm");
                        }
                        else if (text == "getAll") // Toda la información
                        {
                            Console.WriteLine("Text is a get all request");
                            All all = new All()
                            {
                                GPUs = new List<GPU>(),
                                Storages = new List<Storage>()
                            };
                            ManagementObjectSearcher myVideoObject = new ManagementObjectSearcher("select * from Win32_VideoController");
                            foreach (ManagementObject obj in myVideoObject.Get())
                            {
                                all.GPUs.Add(new GPU()
                                {
                                    Name = obj["Name"].ToString(),
                                    Status = obj["Status"].ToString(),
                                    AdapterRAM = obj["AdapterRAM"].ToString(),
                                    AdapterDACType = obj["AdapterDACType"].ToString(),
                                    DriverVersion = obj["DriverVersion"].ToString()
                                });
                            }
                            DriveInfo[] allDrives = DriveInfo.GetDrives();
                            foreach (DriveInfo d in allDrives)
                            {
                                if (d.IsReady == true)
                                {
                                    all.Storages.Add(new Storage()
                                    {
                                        TotalAvailableSpace = d.TotalFreeSpace,
                                        TotalSizeOfDrive = d.TotalSize,
                                        RootDirectory = d.RootDirectory.Name
                                    });
                                }
                            }
                            PerformanceCounter ram = new PerformanceCounter();
                            ComputerInfo infoDevice = new ComputerInfo();
                            ram.CategoryName = "Memory";
                            ram.CounterName = "Available Bytes";
                            all.MemoryRam = new MemoryRam()
                            {
                                TotalPhysicalMemory = infoDevice.TotalPhysicalMemory,
                                TotalFreeSpace = ram.NextValue()
                            };
                            result = JsonConvert.SerializeObject(all);
                            
                            Console.WriteLine("Info sent to client");
                        }
                        else if (text == "exit")
                        {
                            //current.Shutdown(SocketShutdown.Both);
                            //current.Close();
                            //clientSockets.Remove(current);
                            //Console.WriteLine("Cliente desconectado");
                            //return;
                        }
                        else
                        {
                            Console.WriteLine("Peticion Invalida");
                            //byte[] data = Encoding.ASCII.GetBytes("Peticion Invalida");
                            //byte[] data = Encoding.UTF8.GetBytes("Peticion Invalida");
                            //sslStream.Write(data);
                            //current.Send(data);
                            Console.WriteLine("Alerta Enviada");
                        }
                        byte[] outputBuffer = Encoding.UTF8.GetBytes(result);
                        sslStream.Write(outputBuffer);
                       
                    }
                }

            }
            catch (Exception ex)
            {

                MessageBox.Show(""+ex);
            }
        }

        #region SSL

        static bool ValidateCertificate(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            
            return true;

            
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                return true;
            }
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
            {
                return true;
            }
            return false;
        }

        private static X509Certificate getServerCert()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2 foundCertificate = null;
            foreach (X509Certificate2 currentCertificate in store.Certificates)
            {
                if (currentCertificate.IssuerName.Name != null && currentCertificate.IssuerName.Name.Equals("CN=X509CertificateSSL"))
                {
                    foundCertificate = currentCertificate;
                    break;
                }
            }

            return foundCertificate;
        }
        #endregion
    }
}
