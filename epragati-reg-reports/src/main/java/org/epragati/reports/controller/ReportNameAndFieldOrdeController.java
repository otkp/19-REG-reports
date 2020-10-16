package org.epragati.reports.controller;

import java.util.Optional;

import org.epragati.exception.BadRequestException;
import org.epragati.reports.excel.ReportNameAndFieldOrdeService;
import org.epragati.reports.excel.ReportNameAndFieldOrderVO;
import org.epragati.util.GateWayResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * this @RestController is used to process report field for generating excel
 * sheet.
 * 
 * @author bhushan.jyoti
 *
 */
@CrossOrigin
@RestController
public class ReportNameAndFieldOrdeController {
	@Autowired
	private ReportNameAndFieldOrdeService service;
	private static final Logger logger = LoggerFactory.getLogger(ReportNameAndFieldOrdeController.class);

	@PostMapping(path = "/addReportNameAndFieldOrde", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getPaymentReports(@RequestHeader("Authorization") String authString,
			@RequestBody ReportNameAndFieldOrderVO vo) {
		try {
			service.addReport(vo);
			return new GateWayResponse<>(HttpStatus.OK, "success");
		} catch (BadRequestException bex) {
			logger.error("Exception occured for while saving report field  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for while saving report field  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}
	}

	@GetMapping(path = "/getReportNameAndFieldOrde", produces = { MediaType.APPLICATION_JSON_VALUE })
	public GateWayResponse<?> getPaymentReports(@RequestHeader("Authorization") String authString,
			@RequestParam(name = "reportName") String reportName) {
		try {

			Optional<ReportNameAndFieldOrderVO> vo = service.getReport(reportName);
			return (vo.isPresent()) ? new GateWayResponse<>(HttpStatus.OK, vo.get(), "success")
					: new GateWayResponse<>(HttpStatus.OK, Optional.empty(), "success");

		} catch (BadRequestException bex) {
			logger.error("Exception occured for while saving report field  [{}]", bex.getMessage());
			return new GateWayResponse<>(HttpStatus.BAD_REQUEST, bex.getMessage());
		} catch (Exception ex) {
			logger.error("Exception occured for while saving report field  [{}]", ex.getMessage());
			return new GateWayResponse<>(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
		}

	}
}
