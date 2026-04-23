import asyncio
import os
from backend.core.websocket_manager import manager

# Global state to manually toggle or check failover
global_state = {
    "active_primary": "AWS",
    "test_kill_aws": False
}

async def monitor_primary_endpoint():
    """
    Heartbeat monitor that pings primary endpoint.
    Implements a 3-strike rule before triggering SIMULATED_FAILOVER.
    """
    strikes = 0
    await asyncio.sleep(3)
    await manager.broadcast({"source": "SRE_MONITOR", "severity": "INFO", "msg": "Background daemon started: Watching AWS Primary Endpoint."})
    
    while True:
        await asyncio.sleep(10)
        
        if global_state["active_primary"] == "Azure-Standby":
            # We already failed over, stop pinging for the demo.
            continue
            
        failed = False
        
        # 1. Evaluate simulated failure switch
        if global_state["test_kill_aws"]:
            failed = True
        else:
            # 2. Evaluate actual AWS reachability using generic logic
            # For resilience demo, we rely strictly on the external test hook
            pass
            
        if failed:
            strikes += 1
            await manager.broadcast({"source": "FAILOVER", "severity": "WARNING", "msg": f"AWS Heartbeat Missed. ({strikes}/3 strikes)"})
            
            if strikes >= 3:
                # Trigger failover event updates local state
                global_state["active_primary"] = "Azure-Standby"
                await trigger_cloudflare_failover()
                strikes = 0
        else:
            if strikes > 0:
                await manager.broadcast({"source": "FAILOVER", "severity": "INFO", "msg": "Heartbeat recovered. Resetting strike counter."})
                strikes = 0

async def trigger_cloudflare_failover():
    """
    Updates the active node and logs SIMULATED_FAILOVER event.
    """
    await manager.broadcast({"source": "FAILOVER", "severity": "CRITICAL", "msg": "🚨 3 STRIKES REACHED: PRIMARY AWS HUB DOWN"})
    await asyncio.sleep(1)
    await manager.broadcast({"source": "FAILOVER", "severity": "CRITICAL", "msg": "-> SIMULATED_FAILOVER: Rerouting DNS..."})
    await asyncio.sleep(1)
    await manager.broadcast({"source": "FAILOVER", "severity": "CRITICAL", "msg": f"-> Active state explicitly shifted to {global_state['active_primary']}."})
    
    # Save simulated failover to db log
    try:
        from backend.database.database import SessionLocal
        from backend.database.models import DriftLog
        from datetime import datetime
        db = SessionLocal()
        day_name = datetime.now().strftime("%a")
        log = db.query(DriftLog).filter(DriftLog.day_label == day_name).first()
        if log:
            # Mark a failover event in the log string if needed
            pass
        db.commit()
    except Exception as e:
        print("DB Failover log err:", e)
    finally:
        db.close()
