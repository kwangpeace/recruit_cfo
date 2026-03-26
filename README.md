# CFO Candidate Evaluator (공유/저장)

브라우저에서 CFO 후보자 평가 점수를 입력하고, **서버(Postgres)에 저장**해서 여러 사람이 같은 배포 URL에서 **공유 보기**로 함께 확인할 수 있는 간단한 웹앱입니다.

## 로컬 실행

```bash
npm install
npm run dev
```

그 다음 `http://localhost:3000` 접속.

> 주의: 로컬에서 “서버에 저장”까지 테스트하려면 Postgres가 필요합니다. Railway 배포 시에는 Railway Postgres를 붙이면 자동으로 `DATABASE_URL`이 세팅됩니다.

## Railway 배포 (권장)

- **서비스**: Node/Express (이 레포)
- **DB**: Railway Postgres 추가
- **환경변수**: `DATABASE_URL` (Railway가 자동 제공)

배포 후 접속하면 상단의 “서버에 저장”을 누를 때 데이터가 DB에 기록되고, “공유 보기” 탭에 저장된 목록이 나타납니다.

## GitHub 업로드

```bash
git init
git add .
git commit -m "Initial Railway deployable app"
```

이후 GitHub에서 새 레포 생성 후 안내되는 `git remote add origin ...` / `git push -u origin main`을 수행하세요.

