   M S B A M L   `   `   `  ���� U  QLiveCharts.Wpf, Version=0.9.7.0, Culture=neutral, PublicKeyToken=0bc1f845d1ebb8dfG4clr-namespace:LiveCharts.Wpf;assembly=LiveCharts.WpfLiveCharts.Wpf  H DSocketsClient, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null-clr-namespace:SocketsClientSocketsClient    SocketsClient.MainWindow   W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     Dlvc4clr-namespace:LiveCharts.Wpf;assembly=LiveCharts.Wpf     b ^MaterialDesignThemes.Wpf, Version=4.0.0.2422, Culture=neutral, PublicKeyToken=df2a72020bd7962aFmaterialDesign1http://materialdesigninxaml.net/winfx/xaml/themes  'localclr-namespace:SocketsClient  -     � Title$  Client��$	��700��$
��1500�� � WindowStartupLocation$ CenterScreen=�.��� .+�#  MaterialDesignThemes.Wpf.Card  -     Name$ card1��$y�Hidden=�+  %MaterialDesignThemes.Wpf.ShadowAssist   ShadowDepth$ Depth5=�$��32q�$��20,302,1201,40q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��266��$��-27,-37,-23,-21q�.+��� -    ��Name$ txtstorage1�� �� TextAlignment$ Center=�    MaterialDesignBody1TextBlock#��[  $�� ��$��
78,35,69,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949   LiveCharts.Wpf.PieChart  -   $��	piechart1��$��33,56,40,10q�  $
��auto��$��	0,0,0,404q����	#F9424242.���  � RowDefinitions �� $	��140 ��� $��* ��� $
��Auto �.+��� $ ��Resources/socketswhite.png��$��513,0,516,31q�$��Center=�$	��109���� $��1��$��2��$��
50 24 50 0q��� $��Right=�$��2�� �� Orientation$ 
Horizontal=�$��8q��� -    ��Name$ btnSendRequests��$��Enviar Petición��$��Center=�$��	0,120,0,0q�$��2��$	��Top=�$	��150��{�.  �� -   $ btnSendRequest��$y�	Collapsed=�$��Enviar Request��$
��Left=�$��
10,177,0,0q�$	��Top=�$��100                 ��{�.  �� -   	 ��Name$	 
cmbRequest��$��Center=�$	��Top=�$	��364��$��	0,177,0,0q�   MaterialDesignFilledComboBox#��[ )  #MaterialDesignThemes.Wpf.HintAssist
   Hint$
 Seleccione la Petición��   HelperTextFontSize$ 20Q�   
Foreground
 ��� �.  (MaterialDesignThemes.Wpf.TextFieldAssist   UnderlineBrush
 ��� �
�������$��15(�{���  �� Path$ 	IsChecked� �� ElementName$# FilledComboBoxEnabledCheckBox��.@��� .��Toda la información�� .��(&Información de las tarjetas gráficas�� .��0.Información de las unidades de almacenamiento�� .�� Información de la memoria RAM�� .��Desconectar�� $��Información��$
��Left=�$	��130��$��
234,10,0,0q�$	��Top=�$	��225��
�������
���������Z� .��� $��79��$	��Top=�$	��207��$��0,0,0,-1q�.+��� -    ��Name$ lblConnectionStatus��$	��...��$
��Left=�$��	133,1,0,0q�$	��Top=��� $
��Bold"�$
��Left=�$��2,5,0,0q�$	��Top=����	#DDFFFFFFEstado de la conexión:�� $
��Bold"�$
��Left=�$��2,36,0,0q�$	��Top=�
Respuesta:�� -	   $ lblResponse��$	��...��$
��Left=�$��	75,32,0,0q�$	��Top=��� $��Configuración��$
��Left=�$	��162��$	��Top=�$	��200��$��	10,10,0,0q�.��� $
��Left=�$	��100��$	��Top=�$	��190��$��0,0,0,0q�.+��� $��Ingrese la IP:��$
��Bold"�$
��Left=�$��	10,10,0,0q�$	��Top=��� -
    ��Name$ txtIp��$
��Left=�$��23��$��	10,36,0,0q� �� TextWrapping$
 Wrap=�$	��Top=�$	��150���� -   $ btnConnectToServer��$��Conectar a Servidor��$
��Left=�$��	10,64,0,0q�$	��Top=�$	��170���� -   $ txtjson��$
��Left=�$	��326��$��1220,302,0,0q�$
 Wrap=�$	��Top=�$	��262��  -   $ card2��$y�Hidden=�$ Depth5=�$��32q�$��317,302,904,40q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��266��$��-27,-37,-23,-21q�.+��� -   $ txtstorage2��$ Center=�#��[  $�� ��$��
78,35,69,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949  -     Name$ 	piechart2��$��33,56,40,10q�  -   $ card3��$y�Hidden=�$ Depth5=�$��32q�$��617,302,604,41q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��266��$��-27,-37,-23,-21q�.+��� -   $ txtstorage3��$ Center=�#��[  $�� ��$��
78,35,69,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949  -   $ 	piechart3��$��33,56,40,10q�  -   $ card4��$y�Hidden=�$ Depth5=�$��32q�$��914,302,310,40q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��266��$��-27,-37,-23,-21q�.+��� -   $ txtstorage4��$ Center=�#��[  $�� ��$��
78,35,69,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949  -   $ 	piechart4��$��33,56,40,10q�  -   $ cardram��$y�Hidden=�$ Depth5=�$��32q�$��564,302,446,39q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��466��$��-27,-37,-21,-20q�.+��� -   $ txtram��$ Center=�#��[  $�� ��$��
78,35,69,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949  -   $ piechart_ram��$��22,56,228,10q��� $
��Bold"�$
��Left=�$��267,128,0,0q�$	��Top=����	#DD5A5F64Total Free Space�� $
��Bold"�$
��Left=�$��267,199,0,0q�$	��Top=����	#DD5A5F64Total Physical Memory�� -   $ txtspaceram��$
��Left=�$��267,144,0,0q�$	��Top=����	#DD5A5F64�� -   $ txtphysicalram��$
��Left=�$��267,215,0,0q�$	��Top=����	#DD5A5F64  -   $ card_video1��$y�Hidden=�$ Depth5=�$��32q�$��267,300,829,41q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��383��$��-27,-37,-24,-20q�.+��� -   $ 
txtgrafic1��$ Center=�#��[  $�� ��$��
39,35,49,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949�� $
��Bold"�$
��Left=�$��
26,100,0,0q�$	��Top=����	#DD5A5F64Name�� $
��Bold"�$
��Left=�$��212,100,0,0q�$	��Top=����	#DD5A5F64 J� RenderTransformOrigin$ -0.457,-1.562&�Status�� $
��Bold"�$
��Left=�$��
26,184,0,0q�$	��Top=����	#DD5A5F64$ -0.016,0.812&�Adapter RAM�� $
��Bold"�$
��Left=�$��148,255,0,0q�$	��Top=����	#DD5A5F64Driver Version�� $
��Bold"�$
��Left=�$��212,184,0,0q�$	��Top=����	#DD5A5F64Adapter DAC Type�� -   $ 
txtresname��$
��Left=�$��
26,121,0,0q�$	��Top=����	#DD5A5F64$ -0.455,0.062&��� -   $ txtresstatus��$
��Left=�$��212,121,0,0q�$	��Top=����	#DD5A5F64$ 	-1,-2.562&��� -   $ txtresAdapter��$
��Left=�$��
26,205,0,0q�$	��Top=����	#DD5A5F64$ -0.455,0.062&��� -    $ txtresAdapterDAC��$
��Left=�$��212,208,0,0q�$	��Top=����	#DD5A5F64$ 	-1,-2.562&��� -!   $ txtresDriver��$
��Left=�$��148,276,0,0q�$	��Top=����	#DD5A5F64$ 	-1,-2.562&�  -"   $ card_video2��$y�Hidden=�$ Depth5=�$��32q�$��743,300,353,41q�
�������.��� $
��Left=�$	��321��$	��Top=�$	��383��$��-27,-37,-24,-20q�.+��� -#   $ 
txtgrafic2��$ Center=�#��[  $�� ��$��
39,35,49,0q�$��35��$
��auto��$	��Top=�$
��bold"�
����������	#FF494949�� $
��Bold"�$
��Left=�$��
26,100,0,0q�$	��Top=����	#DD5A5F64�� $
�Name���� $
��Bold"�$
��Left=�$��212,100,0,0q�$	��Top=����	#DD5A5F64$ -0.457,-1.562&��� $�Status���� $
��Bold"�$
��Left=�$��
26,184,0,0q�$	��Top=����	#DD5A5F64$ -0.016,0.812&��� $�Adapter RAM���� $
��Bold"�$
��Left=�$��148,255,0,0q�$	��Top=����	#DD5A5F64�� $�Driver Version���� $
��Bold"�$
��Left=�$��212,184,0,0q�$	��Top=����	#DD5A5F64�� $�Adapter DAC Type���� -$   $ txtresname1��$
��Left=�$��
26,121,0,0q�$	��Top=����	#DD5A5F64$ -0.455,0.062&��� -%   $ txtresstatus1��$
��Left=�$��212,121,0,0q�$	��Top=����	#DD5A5F64$ 	-1,-2.562&��� -&   $ txtresAdapter1��$
��Left=�$��
26,205,0,0q�$	��Top=����	#DD5A5F64$ -0.455,0.062&��� -'   $ txtresAdapterDAC1��$
��Left=�$��212,208,0,0q�$	��Top=����	#DD5A5F64$ 	-1,-2.562&��� -(   $ txtresDriver1��$
��Left=�$��148,276,0,0q�$	��Top=����	#DD5A5F64$ 	-1,-2.562&�