import { Router, type IRouter } from "express";
import healthRouter from "./health";
import cyberguardRouter from "./cyberguard";
import agentsRouter from "./agents";

const router: IRouter = Router();

router.use(healthRouter);
router.use(agentsRouter);
router.use(cyberguardRouter);

export default router;
