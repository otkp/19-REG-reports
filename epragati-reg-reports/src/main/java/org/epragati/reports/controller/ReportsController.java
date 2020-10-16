package org.epragati.reports.controller;

import java.io.IOException;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.epragati.aadhaar.AadhaarRequestVO;
import org.epragati.aadhaar.VcrHistoryVO;
import org.epragati.constants.MessageKeys;
import org.epragati.dealer.vo.TrIssuedReportVO;
import org.epragati.exception.BadRequestException;
import org.epragati.jwt.JwtUser;
import org.epragati.master.dao.UserDAO;
import org.epragati.master.dto.UserDTO;
import org.epragati.master.vo.DistrictVO;
import org.epragati.master.vo.FinanceDetailsVO;
import org.epragati.master.vo.RTADashboardVO;
import org.epragati.master.vo.UserVO;
import org.epragati.payment.report.vo.InvoiceDetailsReportVo;
import org.epragati.payment.report.vo.RegReportDuplicateVO;
import org.epragati.payment.report.vo.RegReportVO;
import org.epragati.payment.report.vo.ReportsVO;
import org.epragati.payment.report.vo.ShowCauseReportVo;
import org.epragati.permits.dto.FitnessReportsDemoVO;
import org.epragati.regservice.RegistrationService;
import org.epragati.regservice.mapper.ReportDataVO;
import org.epragati.regservice.vo.ApplicationSearchVO;
import org.epragati.regservice.vo.RegServiceVO;
import org.epragati.regservice.vo.TaxDetailsVO;
import org.epragati.regservice.vo.TowVO;
import org.epragati.reports.service.CheckPostReportService;
import org.epragati.reports.service.DashBoardHelper;
import org.epragati.reports.service.EnforcementReports;
import org.epragati.reports.service.PaymentReportService;
import org.epragati.reports.service.RCCancellationService;
import org.epragati.reports.service.RegistrationReportService;
import org.epragati.reports.service.ReportsExcelExportService;
import org.epragati.reports.service.RevenueReportService;
import org.epragati.reports.service.ShowCauseService;
import org.epragati.reports.service.impl.CheckPostReportServiceImpl;
import org.epragati.reports.service.impl.ReportServiceImpl;
import org.epragati.rta.reports.vo.ActionCountDetailsVO;
import org.epragati.rta.reports.vo.CCOReportVO;
import org.epragati.rta.reports.vo.CheckPostReportsVO;
import org.epragati.rta.reports.vo.CitizenEnclosuresVO;
import org.epragati.rta.reports.vo.DealerReportVO;
import org.epragati.rta.reports.vo.EODReportVO;
import org.epragati.rta.reports.vo.EvcrDetailReportVO;
import org.epragati.rta.reports.vo.FitnessReportVO;
import org.epragati.rta.reports.vo.FreshRCReportVO;
import org.epragati.rta.reports.vo.PageDataVo;
import org.epragati.rta.reports.vo.PermitHistoryDeatilsVO;
import org.epragati.rta.reports.vo.ReportInputVO;
import org.epragati.rta.reports.vo.ReportVO;
import org.epragati.rta.reports.vo.StagingRejectedListVO;
import org.epragati.rta.reports.vo.StoppageReportVO;
import org.epragati.rta.reports.vo.VcrCovAndOffenceBasedReportVO;
import org.epragati.rta.service.impl.DTOUtilService;
import org.epragati.rta.service.impl.service.RTAService;
import org.epragati.security.utill.JwtTokenUtil;
import org.epragati.util.AppMessages;
import org.epragati.util.GateWayResponse;
import org.epragati.util.RequestMappingUrls;
import org.epragati.util.RoleEnum;
import org.epragati.util.payment.ReportsEnum;
import org.epragati.vcr.service.VcrNonPaymentReport;
import org.epragati.vcr.service.VcrService;
import org.epragati.vcr.vo.VcrFinalServiceVO;
import org.epragati.vcr.vo.VcrUnpaidResultVo;
import org.epragati.vcr.vo.VcrVo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
@RequestMapping(RequestMappingUrls.REPORTS)

public class ReportsController {

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	private static final Logger logger = LoggerFactory.getLogger(ReportsController.class);

	@Autowired
	private RegistrationService registrationService;
	
	@Autowired
	private PaymentReportService paymentReportService;

	@Autowired
	private VcrService vcrService;

	@Autowired
	private EnforcementReports enforcementReports;

	@Autowired
	private RevenueReportService revenueReportService;
	@Autowired
	private CheckPostReportServiceImpl checkPostReportServiceImp;

	@Autowired
	private VcrNonPaymentReport vcrNonPaymentReport;

	@Autowired
	private DTOUtilService dtoUtilService;

	@Autowired
	private RCCancellationService rcCancellationService;

	@Autowired
	private ReportServiceImpl reportServiceImpl;

	@Autowired
	private RTAService rTAService;

	@Autowired
	ShowCauseService showCauseService;

	@Autowired
	private RegistrationReportService registrationReportService;

	@Autowired
	private DashBoardHelper dashBoardHelper;
	@Autowired
	private AppMessages appMessages;

	@Autowired
	private UserDAO userDAO;

	@Autowired
	private CheckPostReportService checkPostReportService;

	@Autowired
	private ReportsExcelExportService reportsExcelExportService;

	@PostMapping(path = "/getPaymentsReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getPaymentReports(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentreportVO, Pageable pagable) {
		try {

			Optional<ReportsVO> paymentsReport;
			String reportType = ReportsEnum.DISTRICTREVENUEREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			paymentReportService.districtvalidate(jwtUser, paymentreportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (paymentreportVO.getGateWayType() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "GateWay Type selection is missing");
			}
			if (StringUtils.isEmpty(paymentreportVO.getDistrictName())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "district is missing");

			}
			if (StringUtils.isEmpty(paymentreportVO.getStatus())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "status selection is missing");
			}

			paymentsReport = paymentReportService.getpaymenttransactions(paymentreportVO, pagable);
			if (!paymentsReport.isPresent()) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, paymentsReport.get(), "success");
		} catch (BadRequestException bex) {
			logger.error("Exception occured for payments report  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for payments report  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getDistrictReports", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getDistrictReports(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentreportVO) {
		try {
			String reportType = ReportsEnum.STATEREVENUEREPORT.getDescription();
			List<RegReportVO> paymentsReport;
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			paymentReportService.districtvalidate(jwtUser, paymentreportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (paymentreportVO.getGateWayType() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "GateWay Type selection is missing");
			}

			if (StringUtils.isEmpty(paymentreportVO.getStatus())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "status selection is missing");
			}

			paymentsReport = paymentReportService.getDistrictReports(paymentreportVO);
			if (!paymentsReport.isEmpty()) {
				return new GateWayResponse<>(HttpStatus.OK, paymentsReport, "success");
			}
			return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
		} catch (BadRequestException bex) {
			logger.error("Exception occured for district payments report [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for district payments report   [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/vehicleStrengthReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> vehicleStrengthReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentreportVO) {
		try {
			String reportType = ReportsEnum.VEHICLESTRENGHTREPORT.getDescription();
			if (paymentreportVO.getFromDate() == null || paymentreportVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/To Dates missing ");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			paymentReportService.districtvalidate(jwtUser, paymentreportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			long days = ChronoUnit.DAYS.between(paymentreportVO.getFromDate(), paymentreportVO.getToDate());
			if (days > 180) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
			}
			RegReportVO paymentReportVO = paymentReportService.vehicleStrengthReport(paymentreportVO, jwtUser);
			if (CollectionUtils.isEmpty(paymentreportVO.getVehicleStrength())) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportVO, MessageKeys.MESSAGE_SUCCESS);
		}

		catch (BadRequestException e) {
			logger.error("exception occured for vehicle strength report  [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}

		catch (Exception e) {
			logger.error("exception occured for vehicle strength report  [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "/getDistrictPaymentReports", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getDistrictPaymentReports(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentreportVO, Pageable pagable) {
		try {
			List<RegReportVO> paymentsReport;

			// JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);

			/*
			 * / paymentReportService.districtvalidate(jwtUser, paymentreportVO); if
			 * (jwtUser == null) { return new GateWayResponse<>(HttpStatus.BAD_REQUEST,
			 * MessageKeys.UNAUTHORIZED_USER); }
			 * 
			 * 
			 */

			// paymentReportService.verifyUserAccess(jwtUser, reportType);
			if (paymentreportVO.getGateWayType() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "GateWay Type selection is missing");
			}

			if (StringUtils.isEmpty(paymentreportVO.getStatus())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "status selection is missing");
			}

			if (StringUtils.isNoneBlank(paymentreportVO.getOfficeCode())) {
				Optional<ReportsVO> reportOpt = paymentReportService.getpaymenttransactions(paymentreportVO, pagable);
				if (reportOpt.isPresent()) {
					return new GateWayResponse<>(HttpStatus.OK, reportOpt.get(), "success");

				}
				return new GateWayResponse<>(HttpStatus.OK, "No  Data Found");

			}
			paymentsReport = paymentReportService.PaymentReportData(paymentreportVO, pagable);
			if (!paymentsReport.isEmpty()) {
				return new GateWayResponse<>(HttpStatus.OK, paymentsReport, "success");
			}
			return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
		} catch (BadRequestException bex) {
			logger.error("Exception occured for district payments report [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for district payments report   [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/permitCountReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> permitCountReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO reportVO, Pageable pageble, HttpServletResponse response) {
		try {
			if (reportVO.getFromDate() == null || reportVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/To Dates missing ");
			}
			String reportType = ReportsEnum.PERMITREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);
			long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
			if (days > 180) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
			}

			List<RegReportVO> paymentReportVO = new ArrayList<>();

			paymentReportService.districtvalidate(jwtUser, reportVO);

			if (reportVO.getPermitType() != null && reportVO.getOfficeCode() != null) {
				paymentReportVO = paymentReportService.getPermitDetails(reportVO, pageble);

				if (reportVO.isPermitReportsDataExcel()) {
					paymentReportService.generateExcelForPermitReportsData(paymentReportVO, response);
				}

			}

			else if (StringUtils.isEmpty(reportVO.getDistrictName())) {
				paymentReportVO = paymentReportService.statePermitReport(reportVO, jwtUser);
			}

			else {
				// paymentReportService.districtvalidate(jwtUser, reportVO);
				paymentReportVO = paymentReportService.distPermitReport(reportVO);
			}

			if (reportVO.isPermitReportsExcel()) {
				paymentReportService.generateExcelForPermitReports(paymentReportVO, response);
			}

			if (CollectionUtils.isEmpty(paymentReportVO)) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, paymentReportVO, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured for permit count report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("exception occured for permit count report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@PostMapping(path = "/vcrReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getVcrReport(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, Pageable page) {
		try {
			String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getToDate() != null) {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			RegReportVO report = vcrService.vcrReport(reportVO, jwtUser, page);
			if (CollectionUtils.isEmpty(report.getVcrReport())) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/paymentDetailsExcel")
	public GateWayResponse<?> getpaymentExcel(HttpServletResponse response, @RequestBody RegReportVO paymentReportVO,
			@RequestHeader("Authorization") String authString) throws IOException {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			paymentReportService.verifyUserAccess(jwtUser, ReportsEnum.DISTRICTREVENUEREPORT.getDescription());
			Boolean value = paymentReportService.paymentDetailsExcel(response, paymentReportVO);
			if (value) {
				return new GateWayResponse<>(HttpStatus.OK, null, "success");
			}

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new GateWayResponse<>(HttpStatus.NOT_FOUND, null, "No Data Available");
	}

	@PostMapping(value = "/getRCSuspensionReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getReport(@RequestBody RegReportVO regReportVO,
			@RequestHeader("Authorization") String authString, Pageable page, HttpServletResponse response) {
		try {
			String reportType = ReportsEnum.RCSUSPENSIONREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			long days = ChronoUnit.DAYS.between(regReportVO.getFromDate(), regReportVO.getToDate());
			if (days > 180) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
			}

			if (regReportVO.getFromDate() == null || regReportVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<RegReportVO> regReport = new ArrayList<>();

			if (StringUtils.isEmpty(regReportVO.getDistrictName())) {
				regReport = paymentReportService.suspensionStateCount(regReportVO, jwtUser);
			}

			if (regReportVO.getDistrictName() != null && StringUtils.isEmpty(regReportVO.getOfficeCode())) {
				// paymentReportService.districtvalidate(jwtUser, regReportVO);
				regReport = paymentReportService.suspensionDistCount(regReportVO);
			}
			if (regReportVO.getOfficeCode() != null) {
				regReport = paymentReportService.findAllDetails(regReportVO, page);
			}

			paymentReportService.generateExcelForRcSuspensionReport(regReport, response, regReportVO);

			if (CollectionUtils.isNotEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.OK, regReport, MessageKeys.MESSAGE_SUCCESS);
			}
			return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
		} catch (BadRequestException e) {
			logger.error("Exception occured for RC Suspension report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occured for RC Suspension report [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "ccoReport", produces = { MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getCCOApprovedRejectCount(@RequestHeader("Authorization") String token,
			@RequestBody ReportInputVO inputVO) {
		String officeCode = jwtTokenUtil.getUserDetailsByToken(token).getOfficeCode();
		// List<String> role = jwtTokenUtil.getUserRoleFromToken(token);
		try {

			if (StringUtils.isNotEmpty(officeCode)) {

				Optional<List<CCOReportVO>> ccoReportVO = paymentReportService.getCCOApprovedRejectCount(officeCode,
						inputVO);
				if (ccoReportVO.isPresent()) {
					if (ccoReportVO.get().isEmpty()) {
						return new GateWayResponse<>(HttpStatus.NOT_FOUND, (MessageKeys.MESSAGE_NO_RECORD_FOUND));
					}
					return new GateWayResponse<>(HttpStatus.OK, ccoReportVO.get(), (MessageKeys.MESSAGE_SUCCESS));
				}
				return new GateWayResponse<>(HttpStatus.OK, ccoReportVO.get(), MessageKeys.MESSAGE_SUCCESS);
			}

		} catch (Exception e) {
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		return new GateWayResponse<>(HttpStatus.NOT_FOUND, MessageKeys.MESSAGE_NO_RECORD_FOUND);

	}

	@PostMapping(path = "/getDealerReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getReportDetails(@RequestHeader("Authorization") String authString,
			@RequestBody DealerReportVO dealerVO, Pageable page) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		List<DealerReportVO> dealerReport;
		try {
			String reportType = ReportsEnum.DEALERREPORT.getDescription();
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);
			dealerReport = paymentReportService.getDealerReport(jwtUser, dealerVO, page);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at Dealer Reoprt [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at Dealer Reoprt [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		if (CollectionUtils.isEmpty(dealerReport)) {
			return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
		}

		return new GateWayResponse<>(HttpStatus.OK, dealerReport, MessageKeys.MESSAGE_SUCCESS);

	}

	@PostMapping(path = "/covEnforcementReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> covEnforcementReport(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
			if (days > 180) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
			}
			VcrVo vcrVO = paymentReportService.covEnforcementReport(jwtUser.getId(), jwtUser.getOfficeCode(), reportVO);
			if (CollectionUtils.isEmpty(vcrVO.getEnforcementReport())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, vcrVO, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured cov Enforcement report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured cov Enforcement report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/offenceEnforcementReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> offenceEnforcementReport(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
			if (days > 180) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
			}
			ReportsVO vcrVO = enforcementReports.offenceEnforcementReport(jwtUser.getId(), jwtUser.getOfficeCode(),
					reportVO);

			if (reportVO.isOffenceEnforcementReportExcel()) {
				enforcementReports.generateOffenceEnforcementReportExcel(vcrVO, response);
			}

			if (CollectionUtils.isEmpty(vcrVO.getReport())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_RECORDS);

			}

			return new GateWayResponse<>(HttpStatus.OK, vcrVO, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured offence Enforcement report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured offence Enforcement report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/siezedEnforcementReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> siezedEnforcementReport(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO) {
		try {
			if (reportVO.getFromDate() == null || reportVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from Date/To Date is missing");
			}

			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
			if (days > 180) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
			}

			if (StringUtils.isEmpty(reportVO.getOfficeCode())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "office Code is missing");
			}

			List<VcrFinalServiceVO> vcrVOList = enforcementReports.seizedEnforcementReport(jwtUser.getId(),
					jwtUser.getOfficeCode(), reportVO);
			if (CollectionUtils.isEmpty(vcrVOList)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, vcrVOList, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured in siezed Enforcement report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured in siezed Enforcement report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getFinancierReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getReportDetails(@RequestHeader("Authorization") String authString,
			@RequestBody FinanceDetailsVO financeDetailsVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		List<FinanceDetailsVO> financerReport;
		try {
			if (financeDetailsVO.getFromDate() == null || financeDetailsVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from Date/To Date is missing");
			}
			String reportType = ReportsEnum.FINANCERREPORT.getDescription();
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);
			financerReport = paymentReportService.getFinancierReport(jwtUser, financeDetailsVO);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at financerReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at financerReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		if (CollectionUtils.isEmpty(financerReport)) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
		}

		return new GateWayResponse<>(HttpStatus.OK, financerReport, MessageKeys.MESSAGE_SUCCESS);

	}

	@PostMapping(path = "/getData", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getData(@RequestHeader("Authorization") String authString, @RequestBody RegReportVO regVO,
			Pageable page, HttpServletResponse response) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<RegReportVO> regReport = new ArrayList<>();
			regReport = paymentReportService.getData(jwtUser.getId(), jwtUser.getOfficeCode(), regVO, page);

			paymentReportService.generateExcelForRcSuspensionReport(regReport, response, regVO);

			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, regReport, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at suspensionReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at suspensionReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "/getPermitDataOfficewise", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getPermitData(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO, Pageable page, HttpServletResponse response) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<RegReportVO> regReport = new ArrayList<>();
			regReport = paymentReportService.getPermitData(jwtUser.getOfficeCode(), regVO);
			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}

			if (regVO.isPermitReportsExcel()) {
				paymentReportService.generateExcelForPermitReports(regReport, response);
			}

			return new GateWayResponse<>(HttpStatus.OK, regReport, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at permitReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at permitReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	@GetMapping(path = "/getDistByOfc", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getDistByOfc(@RequestHeader("Authorization") String authString) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			List<DistrictVO> vo = paymentReportService.getDistByOfc(jwtUser.getOfficeCode());
			if (CollectionUtils.isEmpty(vo)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, vo, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred while fetching dist [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred while fetching dist [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	@PostMapping(path = "/getMviForDist", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getMviForDist(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			List<String> mvi = paymentReportService.getMviForDist(regVO.getDistrictId());
			if (CollectionUtils.isEmpty(mvi)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, mvi, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, mvi, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred while fetching mvi for dist [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred while fetching mvi for dist [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "/eodReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getEodReport(@RequestHeader("Authorization") String authString,
			@RequestBody EODReportVO eodVO, Pageable pagable, String applicationNo) {

		PageDataVo eodReportList = null;
		List<ActionCountDetailsVO> eodReport = null;
		try {
			if (eodVO.getFromDate() == null || eodVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/To Dates missing ");
			}

			if (eodVO.getToDate().isAfter(LocalDate.now())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Select valid Dates");
			}
			if (eodVO.getToDate().isBefore(eodVO.getFromDate())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "ToDate Should not be before FromDate");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);

			if (StringUtils.isEmpty(eodVO.getSelectedRole())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Selected Role is Missing");
			}

			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (StringUtils.isNotEmpty(eodVO.getApplicationNo())) {

				RegServiceVO result = paymentReportService.getAllData(eodVO.getApplicationNo());

				return new GateWayResponse<>(HttpStatus.OK, result, MessageKeys.MESSAGE_SUCCESS);
			}

			else if (CollectionUtils.isEmpty(eodVO.getStatusList())) {
				eodReport = paymentReportService.getEodReportCount(jwtUser, eodVO);
				return new GateWayResponse<>(HttpStatus.OK, eodReport, MessageKeys.MESSAGE_SUCCESS);
			}

			eodReportList = paymentReportService.getEodReportList(jwtUser, eodVO, pagable);

			return new GateWayResponse<>(HttpStatus.OK, eodReportList, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured eod report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured eod report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getEodReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getReportsByEOD(@RequestHeader("Authorization") String authString,
			@RequestBody EODReportVO eodVO, Pageable pagable, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			ActionCountDetailsVO report = paymentReportService.eodReportForDept(jwtUser, eodVO, pagable);

			reportsExcelExportService.excelReportsForEod(response, report, eodVO);

			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured eod report  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured eod report  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@GetMapping(path = "/getEodReoprtsDropDown", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getEodReoprtsDropDown(@RequestHeader("Authorization") String authString,
			@RequestParam String role, @RequestParam boolean serviceStatus, @RequestParam boolean module) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (StringUtils.isEmpty(role)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "authorized role is required");
			}
			return new GateWayResponse<>(HttpStatus.OK,
					paymentReportService.getEodReportsDropDown(role, serviceStatus, module),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured eod report  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured eod report  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@PostMapping(path = "/revenueBreakUpSaving", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> breakupPayments(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentreportVO) {
		// JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			revenueReportService.breakupsGroupByOffice(paymentreportVO);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at financerReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at financerReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		return null;

	}

	@PostMapping(path = "/distWiseRevenue", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> revenueReportSum(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentreportVO) {
		try {
			String reportType = ReportsEnum.STATEREVENUEREPORT.getDescription();
			List<RegReportVO> paymentsReport;
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			paymentReportService.districtvalidate(jwtUser, paymentreportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (paymentreportVO.getGateWayType() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "GateWay Type selection is missing");
			}

			if (StringUtils.isEmpty(paymentreportVO.getStatus())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "status selection is missing");
			}

			paymentsReport = revenueReportService.getPaymentsReportCount(paymentreportVO);
			if (!paymentsReport.isEmpty()) {
				return new GateWayResponse<>(HttpStatus.OK, paymentsReport, "success");
			}
			return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
		} catch (BadRequestException bex) {
			logger.error("Exception occured for district payments report [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for district payments report   [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@GetMapping(path = "/getEodReportsRolesDropDown", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getEodReportsRolesDropDown(@RequestHeader("Authorization") String authString,
			@RequestParam boolean value, @RequestParam String selectedRole) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			// if(StringUtils.isEmpty(role)) {
			// return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "authorized role is
			// required");
			// }
			return new GateWayResponse<>(HttpStatus.OK,
					paymentReportService.getEodRolesList(value, selectedRole, jwtUser), MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured eod report  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured eod report  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@GetMapping(path = "/getTaxReport", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getTaxReport(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "prNo") String prNo) {
		List<TaxDetailsVO> report1;

		try {

			if (prNo.equals(null) || prNo == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			report1 = paymentReportService.getTaxReport(prNo.toUpperCase());

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

		return new GateWayResponse<>(report1);
	}

	@PostMapping(path = "/getFitnessDataOfficewise", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getFitnessData(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportDuplicateVO regVO, Pageable page, HttpServletResponse response) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);

		try {
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (regVO.getFromDate().equals(null) || regVO.getToDate().equals(null)
					|| StringUtils.isBlank(regVO.getActionUserName())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Invalid inputs");
			}
			String officeCode = jwtUser.getOfficeCode();

			List<FitnessReportsDemoVO> fitnessReport = paymentReportService.getFitnessData(jwtUser, regVO,
					regVO.getActionUserName(), page, officeCode);

			reportsExcelExportService.generateExcelForFitnessData(response, fitnessReport, regVO);

			return new GateWayResponse<>(HttpStatus.OK, fitnessReport, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException e) {
			logger.error("Exception occurred at fitnessReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at fitnessReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());

		}
	}

	@PostMapping(path = "/checkPostReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> checkPostReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentReportVO,
			@RequestParam(name = "page3rdChk", required = false) String page3rdChk, Pageable page) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null)
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);

			return (StringUtils.isNotEmpty(page3rdChk))
					? new GateWayResponse<>(HttpStatus.OK,
							checkPostReportServiceImp.report3rdPage(paymentReportVO, page), MessageKeys.MESSAGE_SUCCESS)
					: new GateWayResponse<>(HttpStatus.OK, checkPostReportServiceImp.checkPostBased(paymentReportVO),
							MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getVcrNonPaymentsReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getNonPaymentsReport(@RequestHeader("Authorization") String authString, Pageable pagable,
			@RequestBody RegReportVO regReportVO, @RequestParam(name = "selectedRole") String selectedRole) {

		Optional<ReportsVO> paymentsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {

			String role = dtoUtilService.getRole(jwtUser.getId(), selectedRole);
			if (!Arrays.asList(RoleEnum.MVI.getName(), RoleEnum.RTO.getName()).contains(role)) {
				logger.error("Not an Authorised User");
				throw new BadRequestException("Not an Authorised User");
			}
			paymentsReport = vcrNonPaymentReport.vcrNonPaymentReport(regReportVO, pagable);
		} catch (Exception e) {
			logger.error("exception occured for Vcr NonPayments Report [{}]", e.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		if (paymentsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, paymentsReport.get(), "Success");
		}
		return new GateWayResponse<>(HttpStatus.OK, Optional.empty(), MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/generateShowCauseNoForVcr", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> generateShowCauseNoForVcr(@RequestHeader(value = "Authorization") String authString,
			@RequestParam(name = "selectedRole") String selectedRole,
			@RequestBody ApplicationSearchVO applicationSearchVO) {

		try {
			if (StringUtils.isEmpty(selectedRole)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "selectedRole is missing");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (null == jwtUser) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			String role = dtoUtilService.getRole(jwtUser.getId(), selectedRole);
			if (!Arrays.asList(RoleEnum.MVI.getName(), RoleEnum.RTO.getName()).contains(role)) {
				logger.error("Not an Authorised User");
				throw new BadRequestException("Not an Authorised User");
			}

			vcrNonPaymentReport.generateShowCauseNoForVcr(applicationSearchVO, jwtUser.getOfficeCode(),
					jwtUser.getUsername(), role);
		} catch (NullPointerException e) {
			logger.error("Exception occured for non payments report  [{}]", e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for non payments report  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		return new GateWayResponse<>(HttpStatus.OK, "Success");
	}

	@PostMapping(path = "/getShowCauseNoDetailsExistingForVcr", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getShowCauseNoDetailsExistingForVcr(
			@RequestHeader(value = "Authorization") String authString, Pageable pagable,
			@RequestBody RegReportVO regReportVO) {

		Optional<ReportsVO> showCauseReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			showCauseReport = vcrNonPaymentReport.getShowCauseNoDetailsExistingForVcr(regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  getShowCauseNoDetailsExisting [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (showCauseReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, showCauseReport.get(), "Success");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@GetMapping(path = "/getVcrNonPaymentRolesDropDown", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getVcrNonPaymentRolesDropDown(@RequestHeader("Authorization") String authString,
			@RequestParam(name = "officeCode") String officeCode,
			@RequestParam(name = "selectedRole") String selectedRole) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (!Arrays.asList(RoleEnum.MVI.getName(), RoleEnum.RTO.getName()).contains(selectedRole)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			return new GateWayResponse<>(HttpStatus.OK, vcrNonPaymentReport.getVcrNonPaymentRolesDropDown(officeCode),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured eod report  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured eod report  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@PostMapping(path = "/getExcelReport")
	public GateWayResponse<?> getExcelReport(HttpServletResponse response, @RequestBody RegReportVO paymentReportVO,
			@RequestHeader("Authorization") String authString, @RequestParam(name = "reportName") String reportName,
			Pageable pagable) throws IOException {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);

			Boolean value = paymentReportService.getExcel(response, paymentReportVO, reportName, jwtUser.getId(),
					jwtUser.getOfficeCode(), null, pagable);
			if (value) {
				return new GateWayResponse<>(HttpStatus.OK, null, "success");
			}

		} catch (Exception e) {

			e.printStackTrace();
		}
		return new GateWayResponse<>(HttpStatus.NOT_FOUND, null, "No Data Available");
	}

	/*
	 * Reg auto approvals reports
	 */
	@PostMapping(path = "/reportOnRegServicesAutoapprovals", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> reportOnRegServicesAutoapprovals(
			@RequestHeader(value = "Authorization") String authString, Pageable pagable,
			@RequestBody RegReportVO regReportVO) {

		Optional<ReportsVO> autoApprovalsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			autoApprovalsReport = vcrNonPaymentReport.getRegServicesAutoapprovalsDetails(regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  reportOnRegServicesAutoapprovals [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (autoApprovalsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport.get(), "");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/reportOnofficeAndDistWiseAutoapprovals", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> reportOnofficeAndDistWiseAutoapprovals(
			@RequestHeader(value = "Authorization") String authString, Pageable pagable,
			@RequestBody RegReportVO regReportVO) {

		Optional<ReportsVO> autoApprovalsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			autoApprovalsReport = vcrNonPaymentReport.getRegOfficeAndDistAutoapprovalsDetails(regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  reportOnRegServicesAutoapprovals [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (autoApprovalsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport.get(), "");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/getExcelReportByAutoapprovals", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getExcelReportByAutoapprovals(@RequestHeader(value = "Authorization") String authString,
			Pageable pagable, @RequestBody RegReportVO regReportVO, HttpServletResponse response) {

		Optional<ReportsVO> autoApprovalsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			autoApprovalsReport = vcrNonPaymentReport.getExcelReportByAutoapprovals(response, regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  reportOnRegServicesAutoapprovals [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (autoApprovalsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport.get(), "");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/aadharSeedIngApprovalsReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> aadharSeedIngApprovalsReport(@RequestHeader(value = "Authorization") String authString,
			Pageable pagable, @RequestBody RegReportVO regReportVO) {

		Optional<ReportsVO> autoApprovalsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			autoApprovalsReport = paymentReportService.getaadharSeedIngApprovalsReport(regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  aadharSeedIngApprovalsReport [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (autoApprovalsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport.get(), "");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/aadharSeedIngOfficeViewReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> aadharSeedIngOfficeViewReport(@RequestHeader(value = "Authorization") String authString,
			Pageable pagable, @RequestBody RegReportVO regReportVO) {

		Optional<ReportsVO> autoApprovalsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			autoApprovalsReport = paymentReportService.getaadharSeedIngOfficeViewReport(regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  aadharSeedIngApprovalsReport [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (autoApprovalsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport.get(), "");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/getNonPaymentsReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getNonPaymentsReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regReportVO, Pageable pagable, HttpServletResponse response) {

		Optional<ReportsVO> paymentsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		if (null == regReportVO.getPendingQuarter()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "PendingQuarter is missing");
		}
		if (StringUtils.isEmpty(regReportVO.getRole())) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "selectedRole is missing");
		}
		if (null == regReportVO.getQuarterEndDate()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "QuarterEndDate is missing");
		}
		String role = dtoUtilService.getRole(jwtUser.getId(), regReportVO.getRole());
		try {
			if (!RoleEnum.getOfficersForNonPayment().contains(role)) {
				return new GateWayResponse<>(HttpStatus.NOT_FOUND, null, "Invalid Role to access the sevices");
			}
			if (StringUtils.isNotBlank(regReportVO.getCov())) {
				if (Arrays.asList(RoleEnum.CCO.getName(), RoleEnum.MVI.getName(), RoleEnum.AO.getName(),
						RoleEnum.RTO.getName()).contains(role)) {
					paymentsReport = rcCancellationService.nonPaymentReportForCov(regReportVO, jwtUser.getOfficeCode(),
							pagable);
					regReportVO.setOfficeCode(jwtUser.getOfficeCode());
				} else if (Arrays
						.asList(RoleEnum.TC.getName(), RoleEnum.DTCIT.getName(), RoleEnum.DTC.getName(),
								RoleEnum.STA.getName())
						.contains(role) && StringUtils.isNotEmpty(regReportVO.getOfficeCode())) {
					paymentsReport = rcCancellationService.nonPaymentReportForCov(regReportVO,
							regReportVO.getOfficeCode(), pagable);
				}
			} else {
				if (Arrays.asList(RoleEnum.CCO.getName(), RoleEnum.MVI.getName(), RoleEnum.AO.getName(),
						RoleEnum.RTO.getName()).contains(role)) {
					paymentsReport = rcCancellationService.nonPaymentReportForCovCount(regReportVO,
							jwtUser.getOfficeCode());
				} else if (Arrays
						.asList(RoleEnum.TC.getName(), RoleEnum.DTCIT.getName(), RoleEnum.DTC.getName(),
								RoleEnum.STA.getName())
						.contains(role) && StringUtils.isNotEmpty(regReportVO.getOfficeCode())) {
					paymentsReport = rcCancellationService.nonPaymentReportForCovCount(regReportVO,
							regReportVO.getOfficeCode());
				}
			}

			reportsExcelExportService.generateNonPaymentReportVehicleDataExcelCount(paymentsReport, response,
					regReportVO);

		} catch (Exception ex) {
			logger.error("Exception occured   [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

		if (!paymentsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, Optional.empty(), MessageKeys.MESSAGE_NO_DATA);
		}
		return new GateWayResponse<>(HttpStatus.OK, paymentsReport.get(), "Success");
	}

	@PostMapping(path = "/getNonPaymentsDistrictOfficeCountReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getNonPaymentsDistrictOfficeCountReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regReportVO, HttpServletResponse response) {

		Optional<ReportsVO> paymentsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		if (null == regReportVO.getPendingQuarter()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "PendingQuarter is missing");
		}
		if (StringUtils.isEmpty(regReportVO.getRole())) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "selectedRole is missing");
		}
		if (null == regReportVO.getQuarterEndDate()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "QuarterEndDate is missing");
		}
		String role = dtoUtilService.getRole(jwtUser.getId(), regReportVO.getRole());
		try {
			if (!Arrays.asList(RoleEnum.TC.getName(), RoleEnum.DTCIT.getName(), RoleEnum.DTC.getName(),
					RoleEnum.STA.getName()).contains(role)) {
				return new GateWayResponse<>(HttpStatus.NOT_FOUND, null, "Invalid Role to access the sevices");
			}
			if (regReportVO.getDistrictId() != null || RoleEnum.DTC.getName().equals(role)) {
				paymentsReport = rcCancellationService.getOfficeCountReport(regReportVO, role, jwtUser.getOfficeCode());
			} else {
				paymentsReport = rcCancellationService.getDistrictCountReport(regReportVO);
			}

			reportsExcelExportService.generateNonPaymentReportCountExcel(response, paymentsReport, regReportVO);

		} catch (Exception ex) {

			logger.error("Exception occured   [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (!paymentsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, Optional.empty(), MessageKeys.MESSAGE_NO_DATA);
		}
		return new GateWayResponse<>(HttpStatus.OK, paymentsReport.get(), "Success");
	}

	/**
	 * View B Register Details
	 */
	@GetMapping(path = "/viewbregisterdetails", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> viewBregisterDetails(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "prNo") String prNo, @RequestParam(value = "isForView") boolean isforView) {
		Object result;
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			if (prNo.equals(null) || prNo == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			result = reportServiceImpl.getRegisterReportDetails(prNo, true);

		} catch (BadRequestException bre) {
			logger.error("Ëxception occured while fetching the Record ", bre);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bre.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching the Record ", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}
		return new GateWayResponse<>(HttpStatus.OK, result, "");
	}

	@PostMapping(path = "/aadharSeedIngApprovalsForDTCReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> aadharSeedIngApprovalsForDTCReport(
			@RequestHeader(value = "Authorization") String authString, Pageable pagable,
			@RequestBody RegReportVO regReportVO) {

		Optional<ReportsVO> autoApprovalsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			autoApprovalsReport = paymentReportService.getaadharSeedIngApprovalsForDTCReport(regReportVO, pagable);
		} catch (Exception ex) {
			logger.error("Exception occured  aadharSeedIngApprovalsReport [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (autoApprovalsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport.get(), "");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	@PostMapping(path = "/aadharSeedViewDetailsReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> Report(@RequestHeader(value = "Authorization") String authString,
			@RequestBody RegReportVO regReportVO) {

		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {
			ReportDataVO autoApprovalsReport = rTAService.getRegistrationAndTax(regReportVO);
			return new GateWayResponse<>(HttpStatus.OK, autoApprovalsReport, "sucess");
		} catch (BadRequestException ex) {
			logger.error("Exception occured  aadharSeedIngApprovalsReport [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured  aadharSeedIngApprovalsReport [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	/**
	 * ########..Show Cause Status Report...###
	 * 
	 * @param authString
	 * @param pagable
	 * @param showCauseReportVO
	 * @return
	 */
	@PostMapping(path = "/getShowCauseReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getShowCauseReport(@RequestHeader(value = "Authorization") String authString,
			Pageable pagable, @RequestBody ShowCauseReportVo showCauseReportVO, HttpServletResponse response) {

		if (showCauseReportVO.getFromDate() == null || showCauseReportVO.getToDate() == null) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/To Dates missing ");
		}
		List<ShowCauseReportVo> showCauseReport = Collections.emptyList();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {

			if (showCauseReportVO.getIsExcel()) {
				showCauseService.generateShowCauseExcelReport(response, showCauseReportVO, jwtUser.getOfficeCode());
			} else {
				showCauseReport = showCauseService.getShowCauseReport(showCauseReportVO, jwtUser.getOfficeCode());
			}
		} catch (Exception ex) {
			logger.error("Exception occured  getShowCauseReport [{}]", ex);
			logger.debug("Excpetoin in getShowCauseReport :: [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (!showCauseReport.isEmpty()) {
			return new GateWayResponse<>(HttpStatus.OK, showCauseReport, "Success");
		}
		return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
	}

	/*
	 * @PostMapping(value = "/generateShowCauseExcelReport", produces = {
	 * MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE }) public
	 * GateWayResponse<?>
	 * generateShowCauseExcelReport(@RequestHeader("Authorization") String token,
	 * 
	 * @RequestBody ShowCauseReportVo showCauseReportVO, HttpServletResponse
	 * response) { try { JwtUser jwtUser =
	 * jwtTokenUtil.getUserDetailsByToken(token); String officeCode =
	 * jwtUser.getOfficeCode();
	 * logger.info("In Excel Generation with officeCode {}", officeCode);
	 * showCauseService.generateShowCauseExcelReport(response, showCauseReportVO,
	 * officeCode); } catch (BadRequestException e) { logger.debug("{}", e);
	 * logger.info("{}", e); return new GateWayResponse<>(HttpStatus.BAD_REQUEST,
	 * e.getMessage()); } catch (Exception e) { logger.debug("{}", e);
	 * logger.info("{}", e); return new
	 * GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage()); } return
	 * null;
	 * 
	 * }
	 */

	@GetMapping(path = "/getDistrictOffices", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getDistrictOffices(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "districtId") Integer districtId) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			return new GateWayResponse<>(HttpStatus.OK, registrationReportService.getOfficeCodes(districtId),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/getVehicleTypes", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVehicleTypes(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "selectedRole") String selectedRole) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			return new GateWayResponse<>(HttpStatus.OK, registrationReportService.getVehicleType(selectedRole),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/getCovTypes", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getCovTypes(@RequestHeader("Authorization") String authString,
			@RequestBody List<String> category) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			return new GateWayResponse<>(HttpStatus.OK, registrationReportService.getClassOfVehicles(category),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/getVehicleStregthReport", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVehicleStregthReport(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "selectedRole") String selectedRole,
			@RequestParam(value = "districtId", required = false) String districtId,
			@RequestParam(value = "officeCode") String officeCode,
			@RequestParam(value = "vehicleType") String vehicleType,
			@RequestParam(value = "countDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate countDate,
			@RequestParam(value = "groupCategory", required = false) String groupCategory) {
		// @RequestBody VehicleStrengthVO vehicleStrengthVO) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			String role = dtoUtilService.getRole(jwtUser.getId(), selectedRole);
			if (!selectedRole.equals(role)) {
				logger.error("User Role:{}, not mapped to User:{}", selectedRole, jwtUser.getUsername());
				throw new BadRequestException(
						"User Role (" + selectedRole + "), not mapped to User:(" + jwtUser.getUsername() + ")");
			}
			return new GateWayResponse<>(HttpStatus.OK, registrationReportService.getVehicleStrengthReport(selectedRole,
					districtId, officeCode, vehicleType, countDate, groupCategory, jwtUser),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/getVehicleStregthReportExcel", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVehicleStregthReportExcel(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "selectedRole") String selectedRole,
			@RequestParam(value = "districtId", required = false) String districtId,
			@RequestParam(value = "officeCode") String officeCode,
			@RequestParam(value = "vehicleType") String vehicleType,
			@RequestParam(value = "countDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate countDate,
			@RequestParam(value = "groupCategory", required = false) String groupCategory,
			@RequestParam(value = "vehicleStrengthExcel") boolean test, HttpServletResponse response) {
		// @RequestBody VehicleStrengthVO vehicleStrengthVO) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			String role = dtoUtilService.getRole(jwtUser.getId(), selectedRole);
			if (!selectedRole.equals(role)) {
				logger.error("User Role:{}, not mapped to User:{}", selectedRole, jwtUser.getUsername());
				throw new BadRequestException(
						"User Role (" + selectedRole + "), not mapped to User:(" + jwtUser.getUsername() + ")");
			}

			List<ReportVO> reportVo = registrationReportService.getVehicleStrengthReport(selectedRole, districtId,
					officeCode, vehicleType, countDate, groupCategory, jwtUser);

			if (test) {
				registrationReportService.generateVehicleStrengthReportExcel(reportVo, response);
			}

			return new GateWayResponse<>(HttpStatus.OK, reportVo, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/getVehicleStregthReportOfficeDataExcel", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVehicleStregthReportOfficeDataExcel(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "selectedRole") String selectedRole,
			@RequestParam(value = "districtId", required = false) String districtId,
			@RequestParam(value = "officeCode") String officeCode,
			@RequestParam(value = "vehicleType") String vehicleType,
			@RequestParam(value = "countDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate countDate,
			@RequestParam(value = "groupCategory", required = false) String groupCategory,
			@RequestParam(value = "vehicleStrengthOfficeDataExcel") boolean test, HttpServletResponse response) {
		// @RequestBody VehicleStrengthVO vehicleStrengthVO) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			String role = dtoUtilService.getRole(jwtUser.getId(), selectedRole);
			if (!selectedRole.equals(role)) {
				logger.error("User Role:{}, not mapped to User:{}", selectedRole, jwtUser.getUsername());
				throw new BadRequestException(
						"User Role (" + selectedRole + "), not mapped to User:(" + jwtUser.getUsername() + ")");
			}

			List<ReportVO> reportVo = registrationReportService.getVehicleStrengthReport(selectedRole, districtId,
					officeCode, vehicleType, countDate, groupCategory, jwtUser);

			if (test) {
				registrationReportService.generateVehicleStrengthReportOfficeDataExcel(reportVo, response);
			}

			return new GateWayResponse<>(HttpStatus.OK, reportVo, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/getVehicleStregthReportTransportDataExcel", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVehicleStregthReportTransportDataExcel(
			@RequestHeader("Authorization") String authString,
			@RequestParam(value = "selectedRole") String selectedRole,
			@RequestParam(value = "districtId", required = false) String districtId,
			@RequestParam(value = "officeCode") String officeCode,
			@RequestParam(value = "vehicleType") String vehicleType,
			@RequestParam(value = "countDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate countDate,
			@RequestParam(value = "groupCategory", required = false) String groupCategory,
			@RequestParam(value = "vehicleStrengthTransportDataExcel") boolean test, HttpServletResponse response) {
		// @RequestBody VehicleStrengthVO vehicleStrengthVO) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			String role = dtoUtilService.getRole(jwtUser.getId(), selectedRole);
			if (!selectedRole.equals(role)) {
				logger.error("User Role:{}, not mapped to User:{}", selectedRole, jwtUser.getUsername());
				throw new BadRequestException(
						"User Role (" + selectedRole + "), not mapped to User:(" + jwtUser.getUsername() + ")");
			}

			List<ReportVO> reportVo = registrationReportService.getVehicleStrengthReport(selectedRole, districtId,
					officeCode, vehicleType, countDate, groupCategory, jwtUser);

			if (test) {
				registrationReportService.generateVehicleStrengthReportTransportDataExcel(reportVo, response);
			}

			return new GateWayResponse<>(HttpStatus.OK, reportVo, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/getMviNameForDist", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getMviNameForDist(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			List<UserVO> mvi = paymentReportService.getMviNameForDist(regVO.getDistrictId());
			if (CollectionUtils.isEmpty(mvi)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, mvi, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, mvi, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred while fetching mvi for dist [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred while fetching mvi for dist [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "/getCountAndOfficeViceVcrData", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getCountAndOfficeViceVcrData(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, HttpServletResponse response) {
		try {
			String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getFromDate().toString() != ""
					&& reportVO.getToDate() != null && reportVO.getToDate().toString() != "") {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			List<RegReportVO> report = vcrService.getCountAndOfficeViceVcrData(reportVO, jwtUser);
			if (report == null || report.isEmpty()) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}

			if (reportVO.isVcrPaymentReportExcelList()) {
				vcrService.generateVcrPaymentReportsExcelList(report, response);
			}

			if (reportVO.isVcrPaymentReportOfficeDataExcelList()) {
				vcrService.generateExcelListForVcrpaymentReportOfficeData(report, response);
			}

			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getVcrPaidCountForOfficeVice", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getVcrPaidCountForOfficeVice(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO) {
		try {
			String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getFromDate().toString() != ""
					&& reportVO.getToDate() != null && reportVO.getToDate().toString() != "") {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			List<RegReportVO> report = vcrService.getVcrPaidCountForOfficeVice(reportVO, jwtUser);
			if (report == null || report.isEmpty()) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getDistrictViceVcrCount", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getDistrictViceVcrCount(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, Pageable page, HttpServletResponse response) {
		try {
			String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getToDate() != null) {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			ReportsVO report = vcrService.getDistrictViceVcrCount(reportVO, jwtUser);

			if (reportVO.isForExcel()) {

				vcrService.generateDistrictViceVcrCountExcelReport(response, report, jwtUser.getOfficeCode());

			}

			if (reportVO.isMviExcelList()) {

				vcrService.generateExcelListforMVINames(response, report);

			}

			if (report == null) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getNonPaymentsMandalCountReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getNonPaymentsMandalCountReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regReportVO, HttpServletResponse response) {

		Optional<ReportsVO> paymentsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		if (null == regReportVO.getQuarterEndDate()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "QuarterEndDate is missing");
		}
		if (null == regReportVO.getPendingQuarter()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "PendingQuarter is missing");
		}
		if (StringUtils.isEmpty(regReportVO.getRole())) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "selectedRole is missing");
		}
		String role = dtoUtilService.getRole(jwtUser.getId(), regReportVO.getRole());
		try {
			if (Arrays.asList(RoleEnum.CCO.getName(), RoleEnum.MVI.getName(), RoleEnum.AO.getName(),
					RoleEnum.RTO.getName()).contains(role)) {
				paymentsReport = rcCancellationService.getMandalCountReport(regReportVO, jwtUser.getOfficeCode());
			} else if (Arrays
					.asList(RoleEnum.TC.getName(), RoleEnum.DTCIT.getName(), RoleEnum.DTC.getName(),
							RoleEnum.STA.getName())
					.contains(role) && StringUtils.isNotEmpty(regReportVO.getOfficeCode())) {
				paymentsReport = rcCancellationService.getMandalCountReport(regReportVO, regReportVO.getOfficeCode());
			}

			reportsExcelExportService.generateNonPaymentReportCovWiseCountExcel(response, paymentsReport, regReportVO);

		} catch (Exception ex) {
			logger.error("Exception occured   : {}", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (!paymentsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, Optional.empty(), MessageKeys.MESSAGE_NO_DATA);
		}
		return new GateWayResponse<>(HttpStatus.OK, paymentsReport.get(), "Success");
	}

	@PostMapping(path = "/getNonPaymentsReportMandalWiseCov", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getNonPaymentsReportMandalWise(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regReportVO, Pageable pagable, HttpServletResponse response) {

		Optional<ReportsVO> paymentsReport = Optional.empty();
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		if (null == jwtUser) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		if (null == regReportVO.getQuarterEndDate()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "QuarterEndDate is missing");
		}
		if (null == regReportVO.getPendingQuarter()) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "PendingQuarter is missing");
		}
		if (StringUtils.isEmpty(regReportVO.getRole())) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "selectedRole is missing");
		}
		String role = dtoUtilService.getRole(jwtUser.getId(), regReportVO.getRole());
		try {
			if (!RoleEnum.getOfficersForNonPayment().contains(role)) {
				return new GateWayResponse<>(HttpStatus.NOT_FOUND, null, "Invalid Role to access the sevices");
			}
			if (StringUtils.isNotBlank(regReportVO.getCov())) {
				if (Arrays.asList(RoleEnum.CCO.getName(), RoleEnum.MVI.getName(), RoleEnum.AO.getName(),
						RoleEnum.RTO.getName()).contains(role)) {
					paymentsReport = rcCancellationService.nonPaymentMandalWiseReportForCov(regReportVO,
							jwtUser.getOfficeCode(), pagable);
					regReportVO.setOfficeCode(jwtUser.getOfficeCode());
				} else if (Arrays
						.asList(RoleEnum.TC.getName(), RoleEnum.DTCIT.getName(), RoleEnum.DTC.getName(),
								RoleEnum.STA.getName())
						.contains(role) && StringUtils.isNotEmpty(regReportVO.getOfficeCode())) {
					paymentsReport = rcCancellationService.nonPaymentMandalWiseReportForCov(regReportVO,
							regReportVO.getOfficeCode(), pagable);
				}
			} else if (regReportVO.getMandalName() != null) {
				if (Arrays.asList(RoleEnum.CCO.getName(), RoleEnum.MVI.getName(), RoleEnum.AO.getName(),
						RoleEnum.RTO.getName()).contains(role)) {
					paymentsReport = rcCancellationService.nonPaymentMandalWiseReportForCovCount(regReportVO,
							jwtUser.getOfficeCode());
				} else if (Arrays
						.asList(RoleEnum.TC.getName(), RoleEnum.DTCIT.getName(), RoleEnum.DTC.getName(),
								RoleEnum.STA.getName())
						.contains(role) && StringUtils.isNotEmpty(regReportVO.getOfficeCode())) {
					paymentsReport = rcCancellationService.nonPaymentMandalWiseReportForCovCount(regReportVO,
							regReportVO.getOfficeCode());
				}
			}

			reportsExcelExportService.generateNonPaymentReportVehicleDataExcelCount(paymentsReport, response,
					regReportVO);

		} catch (Exception ex) {
			logger.error("Exception occured   : {}", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
		if (!paymentsReport.isPresent()) {
			return new GateWayResponse<>(HttpStatus.OK, Optional.empty(), MessageKeys.MESSAGE_NO_DATA);
		}
		return new GateWayResponse<>(HttpStatus.OK, paymentsReport.get(), "Success");
	}

	@PostMapping(path = "/invoiceDetailsReport", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> invoiceDetailsReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO, HttpServletResponse response, Pageable page) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (150 < ChronoUnit.DAYS.between(regVO.getFromDate(), regVO.getToDate())) {
				throw new Exception("date range should be not more then 150 Days.");
			}
			List<InvoiceDetailsReportVo> list = registrationReportService.invoiceDetailsReport(regVO.getFromDate(),
					regVO.getToDate(), jwtUser.getOfficeCode());
			if (CollectionUtils.isEmpty(list))
				return new GateWayResponse<>(HttpStatus.NO_CONTENT, "NO DATA FOUND");
			if (regVO.isExeclRequired()) {
				Boolean status = paymentReportService.getExcel(response, regVO, "InvoiceDetailsReport",
						jwtUser.getUsername(), jwtUser.getOfficeCode(), list, page);
				if (status)
					return new GateWayResponse<>(HttpStatus.OK, null, MessageKeys.MESSAGE_SUCCESS);
			}
			return new GateWayResponse<>(HttpStatus.OK, list, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching invoiceDetailsReport Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.debug("Ëxception occured while fetching invoiceDetailsReport Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}

	}

	@GetMapping(value = "getDashBoardDetailsCombine", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getRTADashBoardBasedOnRole(@RequestHeader("Authorization") String userId) {
		try {

			Optional<UserDTO> userDetails = userDAO.findByUserId(jwtTokenUtil.getUsernameFromToken(userId));

			if (!userDetails.isPresent()) {
				return new GateWayResponse<>(MessageKeys.NO_AUTHORIZATION);
			}

			RTADashboardVO rtaDashBoardMenu = null;
			rtaDashBoardMenu = dashBoardHelper.getDashBoard(userId);

			return (rtaDashBoardMenu == null || (rtaDashBoardMenu.getAoDashBoard() == null
					&& rtaDashBoardMenu.getCcoDashBoard() == null && rtaDashBoardMenu.getRtoDashBoard() == null))
							? new GateWayResponse<>("Dash Board data Not Available to Display")
							: new GateWayResponse<>(HttpStatus.OK, rtaDashBoardMenu,
									appMessages.getResponseMessage(MessageKeys.MESSAGE_SUCCESS));

		} catch (BadRequestException bre) {
			logger.error("{}", bre.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bre.getMessage());
		} catch (Exception e) {
			logger.error("{}", e);
			return new GateWayResponse<>(HttpStatus.BAD_GATEWAY, e.getMessage());
		}

	}

	@PostMapping(path = "/getCheckPostReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getCheckPostReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentReportVO, Pageable page, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			List<CheckPostReportsVO> checkpost = checkPostReportServiceImp.getCheckPostReport(paymentReportVO);

			reportsExcelExportService.generateExcelForPaymentCheckPostReport(checkpost, paymentReportVO, response);

			return new GateWayResponse<>(HttpStatus.OK, checkpost, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	/**
	 * ============VCR Paid Report =============
	 * 
	 * @param authString
	 * @param reportVO
	 * @param page
	 * @return
	 */
	@PostMapping(path = "/paidVcrReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> paidVcrReport(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, Pageable page, HttpServletResponse response) {
		try {
			String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getToDate() != null) {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			RegReportVO report = vcrService.vcrPaidReport(reportVO, jwtUser, page);
			if (CollectionUtils.isEmpty(report.getVcrReport())) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}

			reportsExcelExportService.generateExcelForVcrPaymentPaidDate(report, response, reportVO);

			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@GetMapping(path = "/getPendingReportReg", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getPendingReportReg(@RequestHeader("Authorization") String userId) {
		try {

			Optional<UserDTO> userDetails = userDAO.findByUserId(jwtTokenUtil.getUsernameFromToken(userId));

			if (!userDetails.isPresent()) {
				return new GateWayResponse<>(MessageKeys.NO_AUTHORIZATION);
			}
			RTADashboardVO rtaDashBoardMenu = null;
			rtaDashBoardMenu = dashBoardHelper.getDashBoardReg(userDetails.get().getOffice().getOfficeCode(), userId);

			if (rtaDashBoardMenu == null || (rtaDashBoardMenu.getCcoDashBoard() == null
					&& rtaDashBoardMenu.getAoDashBoard() == null && rtaDashBoardMenu.getMviDashBoard() == null
					&& rtaDashBoardMenu.getRtoDashBoard() == null)) {
				return new GateWayResponse<>("Dash Board data Not Available to Display");
			}

			return new GateWayResponse<>(HttpStatus.OK, rtaDashBoardMenu,
					appMessages.getResponseMessage(MessageKeys.MESSAGE_SUCCESS));

		} catch (BadRequestException bre) {
			logger.error("{}", bre.getMessage());
			return new GateWayResponse<>(HttpStatus.NOT_FOUND, bre.getMessage());
		} catch (Exception e) {
			logger.error("{}", e);

			return new GateWayResponse<>(HttpStatus.NOT_FOUND, e.getMessage());
		}

	}

	@PostMapping(path = "/covWisevcrReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> covWisevcrReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentReportVO, Pageable page, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			VcrCovAndOffenceBasedReportVO covWiseVcrResult = checkPostReportService.covWisevcrReport(paymentReportVO);

			reportsExcelExportService.generateExcelForCovWiseVcrReport(covWiseVcrResult, paymentReportVO, response);

			return new GateWayResponse<>(HttpStatus.OK, covWiseVcrResult, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/covWiseReportForEvcr", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> covWiseReportForEvcr(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentReportVO, Pageable page, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			VcrCovAndOffenceBasedReportVO covWiseVcrResult = checkPostReportService
					.covWiseReportForEvcr(paymentReportVO);

			reportsExcelExportService.generateExcelForCovWiseVcrReport(covWiseVcrResult, paymentReportVO, response);

			return new GateWayResponse<>(HttpStatus.OK, covWiseVcrResult, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/offenseWisevcrReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> offenseWisevcrReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentReportVO, Pageable page, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			VcrCovAndOffenceBasedReportVO offenceResult = checkPostReportService.offenseWisevcrReport(paymentReportVO);

			reportsExcelExportService.generateExcelForOffenceWiseVcrReport(offenceResult, paymentReportVO, response);

			return new GateWayResponse<>(HttpStatus.OK, offenceResult, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@PostMapping(path = "/offenseWiseReportForEvcr", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> offenseWiseReportForEvcr(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO paymentReportVO, Pageable page, HttpServletResponse response) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			VcrCovAndOffenceBasedReportVO offenceResult = checkPostReportService
					.offenseWiseReportForEvcr(paymentReportVO);

			reportsExcelExportService.generateExcelForOffenceWiseVcrReport(offenceResult, paymentReportVO, response);

			return new GateWayResponse<>(HttpStatus.OK, offenceResult, MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@GetMapping(path = "/getTrIssuedReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getTrIssuedReport(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "fromDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate fromDate,
			@RequestParam(value = "toDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate toDate, Pageable page) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK,
					paymentReportService.getDealerTrIssuedReport(fromDate, toDate, jwtUser, page),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@GetMapping(path = "/getEvcrReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getEvcrReport(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "fromDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate fromDate,
			@RequestParam(value = "toDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate toDate,
			@RequestParam String vcrNumber, @RequestParam(value = "reportName", required = true) String reportName,
			Pageable page) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK,
					vcrService.getEvcrReport(fromDate, toDate, vcrNumber, jwtUser, reportName, page),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getPrintedVcrList", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getPrintedVcrList(@RequestHeader("Authorization") String authString,
			@RequestBody List<String> applicationIds,
			@RequestParam(value = "reportName", required = true) String reportName) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			vcrService.saveEvcrPrintedRecords(jwtUser, applicationIds, reportName);
			return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("Exception Occured For Evcr Printed Records  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("Exception Occured For Evcr Printed Records [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@GetMapping(path = "/getTrIssuedReportForDept", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getTrIssuedReportForDept(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "fromDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate fromDate,
			@RequestParam(value = "toDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate toDate,
			@RequestParam(value = "reportName", required = true) String reportName) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (StringUtils.isEmpty(reportName)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Report Name Not Available");
			}

			return new GateWayResponse<>(HttpStatus.OK,
					paymentReportService.getTotalOfficeWise(fromDate, toDate, jwtUser, reportName),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@GetMapping(path = "/getTrGeneratedExcel", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> invoiceDetailsReport(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "fromDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate fromDate,
			@RequestParam(value = "toDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate toDate,
			@RequestParam(value = "vehicleType", required = true) String vehicleType, HttpServletResponse response,
			@RequestParam(value = "reportName", required = true) String reportName) {
		try {

			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			paymentReportService.generateExcelForTrDetails(vehicleType, jwtUser, fromDate, toDate, response,
					reportName);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching invoiceDetailsReport Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.debug("Ëxception occured while fetching invoiceDetailsReport Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}
		return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_SUCCESS);

	}

	@PostMapping(path = "/getRoadSafetyVcrCount", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getRoadSafetyVcrCount(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, Pageable page, HttpServletResponse response) {
		try {
			// String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			// paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getToDate() != null) {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			ReportVO report = vcrService.getRoadSafetyVcrCount(reportVO, jwtUser);
			if (reportVO.isRoadSafetyExcelMviCount()) {
				vcrService.generateExcelForRoadSafetyMviCount(report, response);
			}

			if (reportVO.isRoadSafetyExcelVcrCount()) {
				vcrService.generateExcelForRoadSafetyVcrCount(report, response);
			}

			if (report == null) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getRoadSafetyVcrDistrictCount", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getRoadSafetyVcrDistrictCount(@RequestHeader("Authorization") String authString,
			@RequestBody VcrVo reportVO, Pageable page, HttpServletResponse response) {
		try {
			String reportType = ReportsEnum.VCRREPORT.getDescription();
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			// paymentReportService.districtvalidate(jwtUser, reportVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			paymentReportService.verifyUserAccess(jwtUser, reportType);

			if (reportVO.getFromDate() != null && reportVO.getToDate() != null) {
				long days = ChronoUnit.DAYS.between(reportVO.getFromDate(), reportVO.getToDate());
				if (days > 180) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select Dates range Between 180 Days");
				}
			}

			ReportVO report = vcrService.getRoadSafetyVcrDistrictCount(reportVO, jwtUser);
			if (reportVO.isRoadSafetyVcrDistrictCountExcel()) {
				reportsExcelExportService.getRoadSafetyVcrDistrictCountExcel(response, report);
			}
			if (report == null) {
				return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_RECORDS);
			}
			return new GateWayResponse<>(HttpStatus.OK, report, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException bex) {
			logger.error("exception occured vcr report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured vcr report  [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	/**
	 * vechicle stoppage report
	 * 
	 */
	@PostMapping(path = "/getvehiclestoppagedata", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getVehicleStoppageData(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<StoppageReportVO> regReport = new ArrayList<>();
			regReport = paymentReportService.fetchVehicleStoppageData(jwtUser.getOfficeCode(), regVO);
			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, regReport, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at vehicleStoppageReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at vehicleStoppageReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@GetMapping(path = "/getTrDetailsReportByOffice", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getTrDetailsReportByOffice(@RequestHeader("Authorization") String authString,
			@RequestParam(value = "fromDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate fromDate,
			@RequestParam(value = "toDate") @DateTimeFormat(pattern = "dd-MM-yyyy") LocalDate toDate,
			@RequestParam(value = "vehicleType", required = true) String vehicleType,
			@RequestParam(value = "reportName", required = true) String reportName, Pageable page) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			if (StringUtils.isEmpty(reportName)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Report Name Not Available");
			}
			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getTrDetailsBasedOnVehicleType(vehicleType,
					jwtUser, fromDate, toDate, reportName, page), MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("exception occured for Check Post Report report  [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());

		} catch (Exception ex) {
			logger.error("exception occured for Check Post Report report [{}]", ex);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}

	@PostMapping(path = "/getregservices", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getCitizenEnclosures(@RequestHeader("Authorization") String authString,
			@RequestBody CitizenEnclosuresVO citizenEnclosuresVO) {

		try {

			if (citizenEnclosuresVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getCitizenServices(citizenEnclosuresVO),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/getenclosures", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getEnclosures(@RequestHeader("Authorization") String authString,
			@RequestBody CitizenEnclosuresVO citizenEnclosuresVO) {

		try {

			if (citizenEnclosuresVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getCitizenEnclosures(citizenEnclosuresVO),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/getevcrreportdistrictwise", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getEvcrReportDistrictWise(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO, HttpServletResponse response) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			Map<String, Long> regReport = new HashMap<>();
			Map<String, Long> regReport1 = null;
			Map<String, Object> finalMapReturned = null;
			List<Map<String, Object>> listFinalReturnedMap = new ArrayList<>();
			regReport = paymentReportService.fetchEvcrReportDistrictWise(jwtUser.getOfficeCode(), regVO);

			regReport1 = regReport.entrySet().stream().sorted((Map.Entry.<String, Long>comparingByKey())).collect(
					Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));

			for (Map.Entry<String, Long> returnMap : regReport1.entrySet()) {
				finalMapReturned = new HashMap<>();
				finalMapReturned.put("name", returnMap.getKey());
				finalMapReturned.put("count", returnMap.getValue());
				listFinalReturnedMap.add(finalMapReturned);
			}

			regVO.setEvcrDetailCount(regReport.entrySet().stream().mapToLong(p -> p.getValue()).sum());
			regVO.seteVcrMap(listFinalReturnedMap);

			// paymentReportService.generateExcelForE(regReport, regVO, response);

			if (regReport.isEmpty()) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, regVO, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at fetching district wise EVCR count [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at fetching district wise EVCR count [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "/displayevcrreportdistrictwise", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> displayEvcrReportDistrictWise(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<VcrFinalServiceVO> regReport = null;
			Map<String, List<VcrFinalServiceVO>> regReport1 = null;
			regReport = paymentReportService.fetchEvcrReportDistrictWiseList(jwtUser.getOfficeCode(), regVO);
			for (VcrFinalServiceVO vcrFinalServiceVO : regReport) {
				vcrFinalServiceVO.getVcr().setCheckedDate(vcrFinalServiceVO.getVcr().getDateOfCheck().toLocalDate());
			}
			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			Map<String, List<VcrFinalServiceVO>> vcrFinalService = regReport.stream()
					.collect(Collectors.groupingBy((VcrFinalServiceVO::getOfficeName)));
			regReport1 = vcrFinalService.entrySet().stream()
					.sorted((Map.Entry.<String, List<VcrFinalServiceVO>>comparingByKey())).collect(Collectors
							.toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1, LinkedHashMap::new));
			List<EvcrDetailReportVO> evcrDetailReportVOList = new ArrayList<>();
			for (Entry<String, List<VcrFinalServiceVO>> returnMap : regReport1.entrySet()) {
				EvcrDetailReportVO evcrDetailReportVO = new EvcrDetailReportVO();
				evcrDetailReportVO.setOfficeName(returnMap.getKey());
				evcrDetailReportVO.setListOfEvcrVos(returnMap.getValue());
				evcrDetailReportVOList.add(evcrDetailReportVO);
			}

			return new GateWayResponse<>(HttpStatus.OK, evcrDetailReportVOList, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at display evcr report districtwise [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at display evcr report districtwise [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "/displayevcrreportbyofficeCodeWise", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> displayEvcrreportbyofficeCodeWise(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<VcrFinalServiceVO> regReport = null;
			Map<String, List<VcrFinalServiceVO>> regReport1 = null;
			regReport = paymentReportService.fetchEvcrReportDistrictWiseList(jwtUser.getOfficeCode(), regVO);
			for (VcrFinalServiceVO vcrFinalServiceVO : regReport) {
				vcrFinalServiceVO.getVcr().setCheckedDate(vcrFinalServiceVO.getVcr().getDateOfCheck().toLocalDate());
			}
			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			Map<String, Object> finalMapReturned = null;
			List<Map<String, Object>> listFinalReturnedMap = new ArrayList<>();
			Map<String, List<VcrFinalServiceVO>> vcrReport = regReport.stream()
					.collect(Collectors.groupingBy((VcrFinalServiceVO::getOfficeName)));

			for (Entry<String, List<VcrFinalServiceVO>> returnMap : vcrReport.entrySet()) {
				finalMapReturned = new HashMap<>();
				finalMapReturned.put("name", returnMap.getKey());
				finalMapReturned.put("count", returnMap.getValue().size());
				listFinalReturnedMap.add(finalMapReturned);
			}
			listFinalReturnedMap.sort(Comparator.comparing(o -> String.valueOf(o.get("name"))));
			return new GateWayResponse<>(HttpStatus.OK, listFinalReturnedMap, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at display evcr report by officeCodeWise [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at display evcr report by officeCodeWise [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

	@PostMapping(path = "contractCarriagePermitReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	private GateWayResponse<?> contractCarriagePermitReport(@RequestBody RegReportVO regVO, Pageable page,
			HttpServletResponse response) {
		try {
			TrIssuedReportVO resultList = paymentReportService.contractCarriagePermitReport(regVO, page);
			reportsExcelExportService.generateExcelForContractCarriage(resultList, response, regVO);
			return new GateWayResponse<>(HttpStatus.OK, resultList, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.info("Exception occured while fetching the contractCarriagePermitReport", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.info("Exception occured while fetching the contractCarriagePermitReport", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}
	}

	@PostMapping(path = "/getregservicesforqueryscreen", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getCitizenServices(@RequestHeader("Authorization") String authString,
			@RequestBody CitizenEnclosuresVO citizenEnclosuresVO) {

		try {

			if (citizenEnclosuresVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK,
					paymentReportService.getCitizenServicesForQueryScreen(citizenEnclosuresVO),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/freshRcReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> freshRcReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {

		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (regVO.getFromDate() == null || regVO.getToDate() == null || regVO.getFrcReport() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates  or frc Status missing");
			}
			List<FreshRCReportVO> regReport = new ArrayList<>();
			regReport = paymentReportService.getFreshRCReportVO(jwtUser.getOfficeCode(), regVO);
			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, regReport, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at freshRcReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at freshRcReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	@PostMapping(path = "/displayIssueOfNocDistrictWise", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> displayIssueOfNocDistrictWise(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		try {
			if (regVO == null || regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/To Dates missing ");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			paymentReportService.districtvalidate(jwtUser, regVO);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			RegReportVO regReportVO = null;
			List<RegReportVO> reportList = new ArrayList<>();
			if (StringUtils.isNoneBlank(regVO.getVehicleType()) && StringUtils.isBlank(regVO.getCov())) {
				regReportVO = paymentReportService.issueOfNocDistrictWiseList(jwtUser, regVO);
				if (CollectionUtils.isEmpty(regReportVO.getCovReport())) {
					return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
				}
				return new GateWayResponse<>(HttpStatus.OK, regReportVO, MessageKeys.MESSAGE_SUCCESS);
			} else if (StringUtils.isNoneBlank(regVO.getVehicleType()) && StringUtils.isNoneBlank(regVO.getCov())) {
				reportList = paymentReportService.fetchIssueOfNocDetails(jwtUser, regVO);
				if (CollectionUtils.isEmpty(reportList)) {
					return new GateWayResponse<>(HttpStatus.OK, MessageKeys.MESSAGE_NO_DATA);
				}
				return new GateWayResponse<>(HttpStatus.OK, reportList, MessageKeys.MESSAGE_SUCCESS);
			}
		} catch (BadRequestException e) {
			logger.error("exception occured while fetching Issue Of NOC  [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("exception occured while fetching Issue Of NOC  [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
		return null;
	}

	@PostMapping(path = "districtwiseDealerOrFinancierReport", produces = { MediaType.APPLICATION_JSON_VALUE })
	private GateWayResponse<?> districtwiseDealerOrFinancierReport(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO, Pageable page) {
		try {
			if (StringUtils.isBlank(regVO.getPrimaryRoleName())) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "please select at least one role.");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (ObjectUtils.isEmpty(jwtUser)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			RegReportVO resultList = paymentReportService.getDistrictwiseDealerOrFinancierDetails(jwtUser, regVO, page);
			return new GateWayResponse<>(HttpStatus.OK, resultList, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.info("Exception occured while fetching the dealer/financier details", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.info("Exception occured while fetching the dealer/financier details", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	/*
	 * For Fitness History at Admin level
	 */
	@PostMapping(path = "/fitnessdetails", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> geFitnesDetails(@RequestHeader("Authorization") String authString,
			@RequestBody FitnessReportVO fitnessReportVO) {

		try {

			if (fitnessReportVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getFitnessDetails(fitnessReportVO),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	/**
	 * Get PR Details for Mining
	 * 
	 *
	 */
	@GetMapping(path = "/getvehicledetailsfromepragathi", produces = { MediaType.APPLICATION_JSON_VALUE })
	private GateWayResponse<?> GetVehicleDetailsFromEpragathi(@RequestParam String prNo) {
		try {
			if (StringUtils.isEmpty(prNo)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Please enter Registration Number");
			}
			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getDetailsForMaining(prNo.toUpperCase()),
					MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.info("Exception occured while fetching the dealer/financier details", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.info("Exception occured while fetching the dealer/financier details", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

	/**
	 * For Permit History Screen at Admin Level
	 */
	@PostMapping(path = "/permitdetailsscreen", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> gePermitDetails(@RequestHeader("Authorization") String authString,
			@RequestBody PermitHistoryDeatilsVO permitHistoryDeatilsVO) {

		try {

			if (permitHistoryDeatilsVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getPermitHistory(permitHistoryDeatilsVO),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/reportForOtherStateVehiclesDataEntry", produces = MediaType.APPLICATION_JSON_VALUE)
	public GateWayResponse<?> reportForOtherStateVehiclesDataEntry(@RequestParam(required = true) String fromDate,
			@RequestParam(required = true) String toDate, @RequestHeader(value = "Authorization") String token) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(token);
			String officeCode = jwtUser.getOfficeCode();
			return new GateWayResponse<>(HttpStatus.OK,
					paymentReportService.reportForOtherStateVehiclesDataEntry(fromDate, toDate, officeCode), "Success");
		} catch (BadRequestException be) {
			logger.error("Ëxception occured" + be.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, be.getMessage());
		} catch (NullPointerException ne) {
			logger.error("Ëxception occured" + ne.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "Sorry there is an error on server", ne.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured" + e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}

	}

	@GetMapping(path = "/dispatchDetailsExcel", produces = MediaType.APPLICATION_JSON_VALUE)
	public GateWayResponse<?> generateExcelForDispatchFormSubmission(@RequestHeader("Authorization") String token,
			@RequestParam String fromDate, @RequestParam String toDate, String fileName, HttpServletResponse response) {

		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(token);
			String officeCode = jwtUser.getOfficeCode();
			paymentReportService.generateExcelForDispatchFormSubmission(response, fromDate, toDate, officeCode,
					fileName);
		} catch (BadRequestException be) {
			logger.error("Ëxception occured" + be.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, be.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured" + e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}

		return null;
	}

	/**
	 * For VCR History Screen at Admin Level
	 */
	@PostMapping(path = "/vcrhistoryscreen", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVcrdetails(@RequestHeader("Authorization") String authString,
			@RequestBody VcrHistoryVO vcrHistoryVO) {

		try {

			if (vcrHistoryVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getVcrDetails(vcrHistoryVO),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/mviPerformanceGetVcrCountDistrictWise", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVcrCountDistrictWise(@RequestHeader("Authorization") String authToken,
			@RequestBody RegReportVO regReportVO) {

		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authToken);
		if (jwtUser == null) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {

			logger.info("-------MVI Performance reports starts-------");
			if (regReportVO.getAllDistrics() != null) {

				RegReportVO result = paymentReportService.getVcrAllDistricts(regReportVO);
				// logger.info("-------MVI Performance reports ends-------");
				return new GateWayResponse<>(result);
			} else {
				RegReportVO result = paymentReportService.getVcrDistrictWiseCount(regReportVO);
				if (result.equals(null) || result == null) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
				}
				return new GateWayResponse<>(result);
			}
		} catch (Exception e) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
		}

	}

	@PostMapping(path = "/mvilistofvcrs", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getMviVcrCount(@RequestHeader("Authorization") String authToken,
			@RequestBody RegReportVO regReportVO) {

		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authToken);
		if (jwtUser == null) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {

			RegReportVO result = paymentReportService.getMviVcrCount(regReportVO);
			if (result.equals(null) || result == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
			}
			return new GateWayResponse<>(result);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
		}
	}

	@PostMapping(path = "/paidVcrListMviWise", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getPaidVcrList(@RequestHeader("Authorization") String authToken,
			@RequestBody RegReportVO regReportVO) {

		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authToken);
		if (jwtUser == null) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {

			List<VcrFinalServiceVO> result = paymentReportService.getPaidVcrListBymviwise(regReportVO);

			if (result.equals(null) || result == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
			}
			return new GateWayResponse<>(result);
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
		}
	}

	/**
	 * Staging Rejection history list
	 */
	@GetMapping(path = "/getrejectionlist", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> get(@RequestHeader("Authorization") String authString, @RequestParam String officeCode) {

		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			return new GateWayResponse<>(HttpStatus.OK, paymentReportService.getRejectionList(officeCode.toUpperCase()),
					MessageKeys.MESSAGE_SUCCESS);

		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@PostMapping(path = "/unpaidVcrListofficeWise", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getUnpaidVcrList(@RequestHeader("Authorization") String authToken,
			@RequestBody RegReportVO regReportVO) {

		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authToken);
		if (jwtUser == null) {
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
		}
		try {

			if (regReportVO.getIsViewData()) {
				VcrUnpaidResultVo result = null;
				result = paymentReportService.getVcrDetailedListOfficeWise(regReportVO);
				if (result.equals(null) || result == null) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
				}
				return new GateWayResponse<>(result);
			} else {
				VcrUnpaidResultVo result = null;
				result = paymentReportService.getVcrUnpaidedCountOfficewise(regReportVO, jwtUser);
				// getVcrUnpaidedCountOfficewise
				if (result.equals(null) || result == null) {
					return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
				}
				return new GateWayResponse<>(result);
			}

		} catch (Exception e) {
			System.out.println(e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
		}
	}
	
	
	/**
	 * Staging Pending Records list
	 */
	@GetMapping(path = "/getStagingPendingReport", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getStagingPendingReport(@RequestHeader("Authorization") String authString,
			@RequestParam String  vehicleType) {

		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			List<StagingRejectedListVO> result = paymentReportService
					.getStagingPendingReport(vehicleType.toUpperCase(), jwtUser.getOfficeCode());
					if (CollectionUtils.isEmpty(result)) {
						return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
					}
					return new GateWayResponse<>(result);
		} catch (BadRequestException bex) {
			logger.error("Exception occured while fetching getStagingPendingReport [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Exception occured while fetching getStagingPendingReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}

	@GetMapping(path = "/getVehicleDetailsByAadharNo", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> getVehicleDetailsByAadharNo(@RequestParam(value = "aadharNo") String aadharNo,
			@RequestHeader(value = "Authorization") String auth) {
		try {
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(auth);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}
			List<AadhaarRequestVO>  aadhaarRequestVO=registrationService.getAdhaarData(aadharNo);
			if(!aadhaarRequestVO.isEmpty()) {
			return new GateWayResponse<>(HttpStatus.OK, aadhaarRequestVO,
					MessageKeys.MESSAGE_SUCCESS);
			}else {
				 String error= "may be  have CancellationofNOC or RCCANCELLATION for this Aadhar No "+aadharNo;
				return new GateWayResponse<>(HttpStatus.OK, aadhaarRequestVO,
						error);
			}
		} catch (BadRequestException be) {
			logger.error("Exception occured while fetching vehicleDetails using AadharNo" + be.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, be.getMessage());
		} catch (Exception e) {
			logger.error("Exception occured while fetching vehicleDetails using AadharNo" + e.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		}

	}
	
	@PostMapping(path = "/towtokendetailsByprNo", produces = { MediaType.APPLICATION_JSON_VALUE,
			MediaType.APPLICATION_XML_VALUE })
	public GateWayResponse<?> towtokendetailsByprNo(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {

		try {

			if (regVO == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "no inputs");
			}
			JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
			if (jwtUser == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.UNAUTHORIZED_USER);
			}

			Optional<TowVO> result = registrationService.towtokendetailsByprNo(regVO.getPrNo());

			if (!result.isPresent()) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "No records found");
			}
			
			return new GateWayResponse<>(HttpStatus.OK, result.get(), MessageKeys.MESSAGE_SUCCESS);
			
		} catch (BadRequestException bex) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", bex);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception e) {
			logger.error("Ëxception occured while fetching Tax Details Report [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());

		}

	}
	
	@PostMapping(path = "/getvehiclestoppagerevocationdata", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getvehiclestoppagerevocationdata(@RequestHeader("Authorization") String authString,
			@RequestBody RegReportVO regVO) {
		JwtUser jwtUser = jwtTokenUtil.getUserDetailsByToken(authString);
		try {
			if (regVO.getFromDate() == null || regVO.getToDate() == null) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, "from/to dates missing");
			}
			List<StoppageReportVO> regReport = new ArrayList<>();
			regReport = paymentReportService.fetchVehicleStoppagerevocationData(jwtUser.getOfficeCode(), regVO);
			if (CollectionUtils.isEmpty(regReport)) {
				return new GateWayResponse<>(HttpStatus.BAD_REQUEST, MessageKeys.MESSAGE_NO_DATA);
			}
			return new GateWayResponse<>(HttpStatus.OK, regReport, MessageKeys.MESSAGE_SUCCESS);
		} catch (BadRequestException e) {
			logger.error("Exception occurred at vehicleStoppageReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, e.getMessage());
		} catch (Exception e) {
			logger.error("Exception occurred at vehicleStoppageReport [{}]", e);
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
		}

	}

}