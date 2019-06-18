using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;

using LogPrinter;

namespace AssistantRobotSupervisingService
{
    public partial class SupervisingService : ServiceBase
    {
        protected ServerFunction sf;
        protected bool ifLoadedSuccess = true;
        protected bool ifCloseFromServerFunction = false;

        public SupervisingService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            sf = new ServerFunction(out ifLoadedSuccess);
            if (!ifLoadedSuccess)
            {
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service close at initial pos.");
                Stop();
                return;
            }

            sf.OnSendCloseService += sf_OnSendCloseService;
            sf.StartListenLoop();
        }

        protected void sf_OnSendCloseService()
        {
            ifCloseFromServerFunction = true;
            Stop();
        }

        protected override void OnStop()
        {
            if (ifLoadedSuccess && !ifCloseFromServerFunction)
            {
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service close from outer side.");
                
                sf.StopListenLoop().Wait();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Video server service ready to closed.");
            }
        }
    }
}
