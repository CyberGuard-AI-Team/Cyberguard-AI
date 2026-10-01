import { Router, type IRouter } from "express";
import healthRouter from "./health";
import cyberguardRouter from "./cyberguard";

const router: IRouter = Router();

router.use(healthRouter);
router.use(cyberguardRouter);

export default router;
