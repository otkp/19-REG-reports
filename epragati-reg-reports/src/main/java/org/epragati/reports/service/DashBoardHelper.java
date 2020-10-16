package org.epragati.reports.service;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.epragati.master.vo.RTADashboardVO;
import org.epragati.rta.service.impl.service.RTAService;
import org.epragati.util.RoleEnum;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class DashBoardHelper {

	@Value("${reg.service.Dynamic.menus:}")
	private String menusUrl;
	@Autowired
	private RestTemplate restTemplate;
	@Autowired
	private RTAService rtaService;

	public Optional<RTADashboardVO> dashBoard1(String userId, String selectedRole) {

		final String uri = menusUrl;
		HttpHeaders headers = new HttpHeaders();
		headers.set("Accept", MediaType.APPLICATION_JSON_VALUE);
		headers.add("Authorization", userId);
		UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(uri).queryParam("roleType", selectedRole);

		HttpEntity<?> entity = new HttpEntity<>(headers);

		HttpEntity<RTADashboardVO> response = restTemplate.exchange(builder.toUriString(), HttpMethod.GET, entity,
				RTADashboardVO.class);

		return Optional.of(response.getBody());

	}

	public RTADashboardVO getDashBoard(String userId) throws ExecutionException {

		// creating thread pool.
		ExecutorService executor = Executors.newFixedThreadPool(3);

		try {
			/**
			 * listing task's and Hand Over to executer service to invoke.
			 */
			List<Future<Optional<RTADashboardVO>>> results = executor.invokeAll(Arrays.asList(
					() -> dashBoard1(userId, RoleEnum.CCO.getName()), () -> dashBoard1(userId, RoleEnum.RTO.getName()),
					() -> dashBoard1(userId, RoleEnum.AO.getName())));
			boolean status = false;
			while (Boolean.TRUE) {
				if (results.get(0).isDone() && results.get(1).isDone() && results.get(2).isDone()) {
					status = true;
					break;
				}
			}
			RTADashboardVO result = new RTADashboardVO();
			return mapResultToReturn(result, results, status);

		} catch (InterruptedException e) {
			e.printStackTrace();
		} finally {
			// shut down the executor manually
			executor.shutdown();
		}

		return null;

	}

	private RTADashboardVO mapData(Optional<RTADashboardVO> data) {
		if (data == null || !data.isPresent())
			return null;
		RTADashboardVO response = data.get();
		response.setOtherServicesList(null);
		return response;

	}

	public Optional<RTADashboardVO> dashBoard2(String userId, String selectedRole, String officeCode) {
		return rtaService.getCitizenDashBoardMenuDetails(officeCode, userId, selectedRole);

	}

	public RTADashboardVO getDashBoardReg(String officeCode, String userId) throws ExecutionException {

		ExecutorService executor = Executors.newFixedThreadPool(4);

		try {
			List<Future<Optional<RTADashboardVO>>> results = executor
					.invokeAll(Arrays.asList(() -> dashBoard2(userId, RoleEnum.CCO.getName(), officeCode),
							() -> dashBoard2(userId, RoleEnum.RTO.getName(), officeCode),
							() -> dashBoard2(userId, RoleEnum.AO.getName(), officeCode),
							() -> dashBoard2(userId, RoleEnum.MVI.getName(), officeCode)));
			boolean status = false;
			while (Boolean.TRUE) {
				if (results.get(0).isDone() && results.get(1).isDone() && results.get(2).isDone()
						&& results.get(3).isDone()) {
					status = true;
					break;
				}
			}
			RTADashboardVO result = new RTADashboardVO();
			return mapResultToReturn(result, results, status);

		} catch (InterruptedException e) {

			e.printStackTrace();
		} finally {
			// shutting down thread pool
			executor.shutdown();
		}

		return null;

	}

	public RTADashboardVO mapResultToReturn(RTADashboardVO result, List<Future<Optional<RTADashboardVO>>> results,
			Boolean status) throws InterruptedException, ExecutionException {
		if (status) {
			for (int i = 0; i < results.size(); i++) {
				if (i == 0)
					result.setCcoDashBoard(mapData(results.get(i).get()));
				if (i == 1)
					result.setRtoDashBoard(mapData(results.get(i).get()));
				if (i == 2)
					result.setAoDashBoard(mapData(results.get(i).get()));
				if (i == 3)
					result.setMviDashBoard(mapData(results.get(i).get()));
			}

		}
		return result;

	}

}
