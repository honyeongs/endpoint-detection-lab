# 출처·저작권 점검

점검일: 2026-10-12. 포함 파일과 공식 라이선스 고지를 확인한 개발 단계 점검이다.
법률 자문, 독창성·저작권 등록 가능성·비침해·분쟁 부재의 보증이 아니다.

## 자체 작성 범위

애플리케이션 코드, 자체 규칙 5개, 시나리오 18개, 정답 manifest, 문서는 AI 개발 지원을 활용해 이 프로젝트에서 작성했다.
기존 상용 EDR 화면·코드·룰·탐지 데이터셋을 복제하지 않았다.
외부 Sigma 규칙이나 테스트 로그를 가져오지 않았고, 실제 악성 파일이나 타인·회사 로그를 포함하지 않았다.
AI 지원 작성이라는 사실이 독점 권리나 타 저작물과의 비유사성을 자동 보장하지는 않는다.
AI 산출물 관련 판단은 [한국저작권위원회 안내 자료](https://www.copyright.or.kr/information-materials/publication/research-report/view.do?brdctsno=52591)와 전문 검토를 참고한다.
해당 안내서 본문·이미지는 이 저장소에 재배포하지 않는다.

## 포함한 외부 자산

Lucide 아이콘 13개만 포함한다. 공식 [ISC 라이선스](https://lucide.dev/license)는 복제·배포 시 저작권·허가 고지의 보존을 요구한다.
원본 라이선스 파일과 Feather 유래 MIT 고지를 변경하지 않고 동봉했으며 체크섬으로 변경 여부를 검사한다.
패키지 버전은 로컬 원본 package.json에서 확인한 `lucide-static 1.55.0`이다.

Python·브라우저·개발 도구 자체는 번들하지 않는다. 런타임 추가 패키지는 없다.
향후 실행 파일로 Python을 묶거나 새 라이브러리·폰트·룰·로그를 넣으면 재배포 조건과 고지를 다시 확인해야 한다.

## Sysmon 재배포 금지 경계

[Microsoft의 Sysinternals 라이선스 FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq)는 제3자 재배포 라이선스를 제공하지 않는다고 설명한다.
따라서 이 프로젝트는 Sysmon 실행 파일·소스·설치기를 포함하거나 자동 설치하지 않는다.
필요한 사용자는 공식 배포처에서 [해당 약관](https://learn.microsoft.com/en-us/sysinternals/license-terms)을 확인하고 별도로 준비한다.
XML 필드 형식은 상호운용 목적의 입력이며 Microsoft 문서 전체나 예제 설정을 복제하지 않았다.
Microsoft·Sysmon 명칭은 호환 입력 설명에만 사용하며 공식 제휴·인증을 표시하지 않는다.

## 자체 소스 라이선스

아직 MIT·Apache 등 자체 코드 재사용 라이선스를 지정하지 않았다. 소유자 승인 없이 재사용·상업 배포 허가를 부여하지 않는다.
공개 GitHub의 열람·포크와 별도의 재사용 라이선스는 다르다. [GitHub의 라이선스 안내](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)를 참고한다.
사용자가 판매·외부 재배포·라이선스 부여를 결정할 때 관련 권리·약관·개인정보 사항을 별도 검토해야 한다.

## 자동 점검의 범위

`python tools/check_publication.py`는 자산 해시·고지, 합성 표본 일치, 표준 라이브러리 런타임,
몇 가지 비밀 패턴·바이너리·원본 로그 포함 여부를 검사한다.
이는 유사 코드 검색·특허 분석·상표 검토·모든 자격 증명 탐지·법률 검토를 대신하지 않는다.
