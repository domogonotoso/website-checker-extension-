"use strict";

// Evidence와 설명 생성기의 경계다. 향후 구현에서는 이 함수 내부에서 원하는
// provider를 호출할 수 있지만, 현재는 네트워크나 모델을 전혀 사용하지 않는다.
async function requestExplanation(evidence) {
  void evidence;
  return {
    status: "unavailable",
    text: "아직 설명 분석기가 연결되지 않았습니다."
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "REQUEST_EXPLANATION") return false;

  requestExplanation(message.evidence).then(sendResponse);

  // Promise가 끝난 뒤 응답할 수 있도록 메시지 채널을 유지한다.
  return true;
});
